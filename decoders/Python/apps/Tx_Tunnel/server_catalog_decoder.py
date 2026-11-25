#!/usr/bin/env python3
"""SP-DECODE server-side catalog decoder for Tx Tunnel v1.10.11.3.

Bridge contract (see cloud/workers/python/catalog_vpn_bridge.py): the
broker downloads the live catalog (POST
https://strongteam.co/api/txtunnelnew/ with body
hash=xsandokUpdatex) and passes the raw envelope text here; run()
returns the decrypted catalog as one JSON string.

Layers (see txtunnel.py): the body is one Argon2id + AES-256-GCM
envelope (password P17, fallback P32); decrypt_catalog_fields then
decrypts every individually-encrypted field generically; the result
is audited field by field and the decode FAILS CLOSED if any
envelope-shaped value remains (audit_decrypted_catalog: 0 remaining
on the live catalog). The result JSON carries NO download API.

VERIFIED_LIVE 2026-11-25: catalog v66.87, 30 servers, 651 networks,
0 encrypted values remaining.
"""
from __future__ import annotations

import json

if __package__:
    from .txtunnel import (
        audit_decrypted_catalog,
        decrypt_catalog_envelope,
        decrypt_catalog_fields,
    )
else:
    from txtunnel import (
        audit_decrypted_catalog,
        decrypt_catalog_envelope,
        decrypt_catalog_fields,
    )


class DecodeError(ValueError):
    pass


def decode_catalog(data: bytes) -> dict:
    """Raw envelope text (bytes) -> fully-decrypted catalog dict.

    The live body is one Argon2id + AES-256-GCM envelope; a plain JSON
    catalog (the historical 'plain' mode, still accepted by the old
    codec.open_document) is accepted as-is. The decoded document must
    be a catalog (Version string, Servers/Networks lists of records):
    a file wire (one network profile) is rejected, like the old codec.
    """
    if not isinstance(data, bytes) or not data:
        raise DecodeError("Catálogo vacío.")
    try:
        text = data.decode("utf-8-sig").strip()
    except UnicodeError:
        raise DecodeError("Catálogo no UTF-8.") from None
    if not text:
        raise DecodeError("Catálogo vacío.")
    if text.startswith("{"):
        try:
            catalog = json.loads(text)
        except ValueError:
            raise DecodeError("Catálogo inválido o incompatible con Tx Tunnel v1.10.") from None
    else:
        try:
            plain, _which = decrypt_catalog_envelope(text)
            catalog = json.loads(plain)
        except (ValueError, TypeError):
            raise DecodeError("Catálogo inválido o incompatible con Tx Tunnel v1.10.") from None
    if (not isinstance(catalog, dict)
            or not isinstance(catalog.get("Version"), str)
            or not all(isinstance(catalog.get(key), list) for key in ("Servers", "Networks"))
            or not all(isinstance(row, dict) for key in ("Servers", "Networks") for row in catalog[key])):
        raise DecodeError("Catálogo inválido o incompatible con Tx Tunnel v1.10.")
    catalog, _stats = decrypt_catalog_fields(catalog, workers=4)
    # workers=4: el descifrado completo del vivo son ~3.280 derivaciones
    # Argon2id (~49 ms c/u, ~166 s en secuencial), por encima del cap
    # CATALOG_TIMEOUT_SECONDS=120 del worker (engine.py); con 4 procesos
    # baja a ~45 s (precedente VLX, decode_fields workers=4). La salida
    # es byte-identica a la secuencial.
    audit = audit_decrypted_catalog(catalog)
    if not audit.get("ok"):
        raise DecodeError(
            "Catálogo con valores sin descifrar: %s" % audit.get("remaining")
        )
    return catalog


def run(data: bytes) -> str:
    """Bridge entry point: bytes -> JSON string."""
    return json.dumps(decode_catalog(data), ensure_ascii=False, indent=2) + "\n"
