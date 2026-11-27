#!/usr/bin/env python3
"""SP-DECODE server-side catalog decoder for ExoticFast VIP "Rk1".

Bridge contract (see cloud/workers/python/catalog_vpn_bridge.py): the
broker downloads the live catalog (plain GET
https://exoticfastvip.xyz/api/app?json=21dbd51eae6e8e810f71) and passes
the raw envelope text here; run() returns the decrypted catalog as one
JSON string.

Layers (see exoticfastvip.py): block-alphabet -> Base64 -> AES-256-CBC
(IV zero, key SHA256("QHRlY2hub3JlMjQ=\\n" + HEX_UPPER(key)), live key
tried first, fallback second), then every j0 field (XXTEA + Base64)
is decrypted. The result JSON carries NO download API.

VERIFIED_LIVE 2026-11-27: catalog v5.8, 6 servers (0 free, 6 PREMIUM),
13 networks, 0 SSL networks. Re-fetch 2026-11-27 byte-identical.

HONEST LIMITS: the vless:// templates of SERVER 1 and SERVER 2 carry
placeholders ([rkhost]/[rkkey]) that no code in this build replaces;
they are kept verbatim. No live connection was tested (all servers
PREMIUM, auth uses the user's login).
"""
from __future__ import annotations

import json

if __package__:
    from .exoticfastvip import decrypt_catalog, outer_decrypt_any
else:
    from exoticfastvip import decrypt_catalog, outer_decrypt_any


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
        catalog = decrypt_catalog(json.loads(outer_decrypt_any(text)))
    except (ValueError, TypeError):
        raise DecodeError("Catálogo inválido o incompatible con ExoticFast VIP Rk1.") from None
    if not isinstance(catalog, dict):
        raise DecodeError("Catálogo sin JSON válido.")
    return catalog


def run(data: bytes) -> str:
    """Bridge entry point: bytes -> JSON string."""
    return json.dumps(decode_catalog(data), ensure_ascii=False, indent=2) + "\n"
