#!/usr/bin/env python3
"""SP-DECODE server-side catalog decoder for ThaiVPN Connect 2.4.

Bridge contract (see cloud/workers/python/catalog_vpn_bridge.py): the
broker does a plain GET on https://thaivapp.my.id/app/thvpn.json and
passes the raw Base64 blob here; run() returns the decrypted catalog
as one JSON string.

Layers (see thaivpn.py): outer XXTEA (delta 772515655, key "aluya20"
zero-padded to 16 bytes) -> JSON with Version / Servers / Networks /
setOpenVPN; inner Base64 fields (ServerIP, Username, Password,
PublicKey, UDPConfig, setOpenVPN, Sni, Payload, SquidProxy,
ServerDNS, ...) decoded at runtime by decode_catalog().

HONEST LIMIT: if any value still looks Base64-encoded after decoding
(find_leftover_encoded), it is kept verbatim, never dropped, and the
result carries a decryptionStatus block with the count and the
LOCATIONS only (never the raw values), so the gateway and the engine
can mark the catalog partial (same shape as Katiba VPN).
The result JSON carries NO download API.

VERIFIED_LIVE 2026-11-27: catalog v17.9, 1 server, 24 networks,
0 leftover encoded values. Re-fetch 2026-11-27 byte-identical to
the delivered sample.
"""
from __future__ import annotations

import json

if __package__:
    from .thaivpn import decode_catalog, decrypt_blob, find_leftover_encoded
else:
    from thaivpn import decode_catalog, decrypt_blob, find_leftover_encoded


class DecodeError(ValueError):
    pass


def decode_catalog_blob(data: bytes) -> dict:
    """Raw blob bytes (Base64 text) -> fully-decrypted catalog dict."""
    if not isinstance(data, bytes) or not data:
        raise DecodeError("Catálogo vacío.")
    try:
        text = data.decode("utf-8-sig").strip()
    except UnicodeError:
        raise DecodeError("Catálogo no UTF-8.") from None
    if not text:
        raise DecodeError("Catálogo vacío.")
    try:
        raw = decrypt_blob(text)
        catalog = decode_catalog(raw)
    except (ValueError, TypeError):
        raise DecodeError(
            "Catálogo inválido o incompatible con ThaiVPN Connect 2.4."
        ) from None
    if not isinstance(catalog, dict):
        raise DecodeError("Catálogo sin JSON válido.")
    leftovers = find_leftover_encoded(catalog)
    if leftovers:
        catalog["decryptionStatus"] = {
            "complete": False,
            "unresolvedFields": len(leftovers),
            "locations": leftovers,
        }
    return catalog


def run(data: bytes) -> str:
    """Bridge entry point: bytes -> JSON string."""
    return json.dumps(decode_catalog_blob(data),
                      ensure_ascii=False, indent=2) + "\n"
