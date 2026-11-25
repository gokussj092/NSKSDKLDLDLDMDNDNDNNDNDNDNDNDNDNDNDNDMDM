#!/usr/bin/env python3
"""SP-DECODE server-side catalog decoder for IRFAN VPN V3.

Bridge contract (see cloud/workers/python/catalog_vpn_bridge.py): the
broker downloads the live catalog (GET
https://strongteam.co/api/irfan/irfan1.txt, User-Agent: IRFAN VPN)
and passes the raw envelope text here; run() returns the decrypted
catalog as one JSON string.

Layers (see irfanvpn.py): the body is one AES-256-GCM envelope
(password II) whose plaintext is a ConfigData JSON object; every
string field inside is itself an envelope decrypted with password I
(decrypt_catalog). The result JSON carries NO download API.

VERIFIED_LIVE 2026-11-25: catalog v2.8, 3 servers, 63 networks.
"""
from __future__ import annotations

import json

if __package__:
    from .irfanvpn import PASSWORD_II, decrypt_catalog, decrypt_envelope
else:
    from irfanvpn import PASSWORD_II, decrypt_catalog, decrypt_envelope


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
        plain = decrypt_envelope(text, PASSWORD_II)
    except (ValueError, TypeError, KeyError):
        raise DecodeError("Catálogo inválido o incompatible con IRFAN V3.") from None
    doc = decrypt_catalog(plain)
    if not isinstance(doc, dict):
        raise DecodeError("Catálogo sin JSON válido.")
    return doc


def run(data: bytes) -> str:
    """Bridge entry point: bytes -> JSON string."""
    return json.dumps(decode_catalog(data), ensure_ascii=False, indent=2) + "\n"
