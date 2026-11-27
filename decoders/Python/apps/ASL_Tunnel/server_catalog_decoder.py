#!/usr/bin/env python3
"""SP-DECODE server-side catalog decoder for ASL TUNNEL 3.0.

Bridge contract (see cloud/workers/python/catalog_vpn_bridge.py): the
broker downloads the live catalog (plain GET
https://raw.githubusercontent.com/th3fre/Testing/refs/heads/main/Alt)
and passes the raw Base64 envelope text here; run() returns the
decrypted catalog as one JSON string.

Layers (see asltunnel.py): Base64 -> XXTEA (custom delta 0x9A7393B4)
-> JSON, then every field decrypted: servers/top level with AES/CFB,
tweaks with AES/CBC, nested V2ray/SlowDNS/UDP objects with AES/CFB.
The result JSON carries NO download API.

VERIFIED_LIVE 2026-11-27: catalog v20.10, 35 servers (all free,
NoobLevel 0), 292 tweaks (124 with Payload). Re-fetch 2026-11-27
byte-identical. 38 nested encrypted values verified, 0 failures; no
encrypted value remains in the delivered JSON.

HONEST LIMIT: the app's own asl://<20 chars> cloud-export link is
NOT implemented: its resolution endpoint was never identified (no
real exported link sample). It is documented, not registered.
"""
from __future__ import annotations

import json

if __package__:
    from .asltunnel import decrypt_alt, decrypt_catalog
else:
    from asltunnel import decrypt_alt, decrypt_catalog


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
        raw = decrypt_alt(text)
        if raw is None:
            raise ValueError("XXTEA decrypt failed")
        catalog = decrypt_catalog(json.loads(raw.decode("utf-8")))
    except (ValueError, TypeError, UnicodeDecodeError):
        raise DecodeError("Catálogo inválido o incompatible con ASL TUNNEL 3.0.") from None
    if not isinstance(catalog, dict):
        raise DecodeError("Catálogo sin JSON válido.")
    return catalog


def run(data: bytes) -> str:
    """Bridge entry point: bytes -> JSON string."""
    return json.dumps(decode_catalog(data), ensure_ascii=False, indent=2) + "\n"
