#!/usr/bin/env python3
"""SP-DECODE server-side catalog decoder for PULSE TUNNEL VPN 1.7.

Bridge contract (see cloud/workers/python/catalog_vpn_bridge.py): the
broker downloads the live catalog (GET
https://xxxbeeghub.com/api/app?json=a1c4f329af86d98a93ed) and passes
the raw S1. signed blob here; run() returns the decrypted catalog as
one JSON string.

The blob is an RSA-signed (S1.) AES-GCM envelope; decode_catalog_fields
decrypts every XXTEA-encrypted field (servers, networks, top-level).
Dropped on purpose from the result: update_api, auth_api and
notice_api — they are catalog download APIs, never part of the
result JSON.

VERIFIED_LIVE 2026-11-25: catalog v1.0.102, 9 servers (all premium),
1,077 networks, 201 payloads.
"""
from __future__ import annotations

import json

if __package__:
    from .pulsetunnel import (
        decode_catalog_fields,
        parse_signed_catalog,
        verify_signature,
    )
else:
    from pulsetunnel import (
        decode_catalog_fields,
        parse_signed_catalog,
        verify_signature,
    )

# Result keys that are download APIs, never served in the result JSON.
_DROPPED_API_KEYS = ("update_api", "auth_api", "notice_api")


class DecodeError(ValueError):
    pass


def decode_catalog(data: bytes) -> dict:
    """Raw S1. blob (bytes) -> fully-decrypted catalog dict."""
    if not isinstance(data, bytes) or not data:
        raise DecodeError("Catálogo vacío.")
    try:
        blob = data.decode("utf-8-sig").strip()
    except UnicodeError:
        raise DecodeError("Catálogo no UTF-8.") from None
    if not blob:
        raise DecodeError("Catálogo vacío.")
    if verify_signature(blob) is False:
        raise DecodeError("Firma RSA del catálogo inválida.")
    try:
        plain = parse_signed_catalog(blob)
    except (ValueError, TypeError):
        raise DecodeError("Catálogo inválido o incompatible con PULSE 1.7.") from None
    try:
        doc = json.loads(plain)
    except ValueError:
        raise DecodeError("Catálogo descifrado sin JSON válido.") from None
    if not isinstance(doc, dict):
        raise DecodeError("Catálogo sin JSON válido.")
    doc = decode_catalog_fields(doc)
    for key in _DROPPED_API_KEYS:
        doc.pop(key, None)
    return doc


def run(data: bytes) -> str:
    """Bridge entry point: bytes -> JSON string."""
    return json.dumps(decode_catalog(data), ensure_ascii=False, indent=2) + "\n"
