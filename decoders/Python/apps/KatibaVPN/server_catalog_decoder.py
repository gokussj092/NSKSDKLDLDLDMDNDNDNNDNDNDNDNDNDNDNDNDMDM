#!/usr/bin/env python3
"""SP-DECODE server-side catalog decoder for Katiba VPN v1.11.06.1.

Bridge contract (see cloud/workers/python/catalog_vpn_bridge.py): the
broker downloads the live catalog (POST
https://strongteam.co/api/katibanew/ with body hash=xsandokUpdatex)
and passes the raw envelope text here; run() returns the decrypted
catalog as one JSON string.

Layers (see katiba.py): the body is one Argon2id + AES-256-GCM
envelope (password P17, fallback P32) whose plaintext is the catalog
JSON; decrypt_catalog_full then decrypts every individually-encrypted
field (servers, networks, top-level) with the remaining passwords.

HONEST LIMIT: 21 values in 15 networks do NOT decrypt with any key
in the APK (the key is not in the APK). They are kept verbatim, never
dropped, and the result carries a decryptionStatus block with the
count and the LOCATIONS only (never the raw values), so the gateway
and the engine can mark the catalog partial:
{"complete": false, "unresolvedFields": 21, "locations": [...]}.
The result JSON carries NO download API.

VERIFIED_LIVE 2026-11-25: catalog v1.12, 57 servers, 235 networks,
21 values in 15 networks left undecrypted (key not in APK).
"""
from __future__ import annotations

import json

if __package__:
    from .katiba import decrypt_catalog, decrypt_catalog_full
else:
    from katiba import decrypt_catalog, decrypt_catalog_full


class DecodeError(ValueError):
    pass


def decode_catalog(data: bytes) -> dict:
    """Raw envelope text (bytes) -> fully-decrypted catalog dict."""
    if not isinstance(data, bytes) or not data:
        raise DecodeError("Catálogo vacío.")
    try:
        text = data.decode("utf-8-sig").strip()
    except UnicodeError:
        raise DecodeError("Catálogo no UTF-8.") from None
    if not text:
        raise DecodeError("Catálogo vacío.")
    try:
        raw = decrypt_catalog(text)
        catalog = json.loads(raw)
    except (ValueError, TypeError):
        raise DecodeError("Catálogo inválido o incompatible con Katiba v1.11.") from None
    if not isinstance(catalog, dict):
        raise DecodeError("Catálogo sin JSON válido.")
    out, failures = decrypt_catalog_full(catalog)
    if failures:
        out["decryptionStatus"] = {
            "complete": False,
            "unresolvedFields": len(failures),
            "locations": [location for location, _raw in failures],
        }
    return out


def run(data: bytes) -> str:
    """Bridge entry point: bytes -> JSON string."""
    return json.dumps(decode_catalog(data), ensure_ascii=False, indent=2) + "\n"
