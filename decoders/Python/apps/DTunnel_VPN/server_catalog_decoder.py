#!/usr/bin/env python3
"""SP-DECODE server-side catalog decoder for DTunnel VPN 4.5.8.

Bridge contract (see cloud/workers/python/catalog_vpn_bridge.py): the
broker downloads the live catalog over gRPC TLS
(grpc.dtunnel.com.br:443, service com.app.config.ConfigService /
getConfigsV2, request {user_id}) with the dedicated downloader
downloadDtunnelVpn in cloud/web/lib/server-vpn-provider.mjs, which
extracts the response field ``data`` (an AES-256-GCM envelope string)
and passes it here; run() returns the decrypted catalog as one JSON
string.

The ``data`` string decrypts (key travels inline in the response) to
a JSON LIST of 16 profiles — there is no Version/Servers/Networks
object, so the gateway validates this provider with the generic
server-vpn branch only. The result JSON carries NO download API and
NO user_id: the server secret lives only in the
SPDECODE_DTUNNEL_VPN_REQUEST_ID environment variable, never in the repo.

VERIFIED_LIVE 2026-11-25: catalog v436, 16 profiles, all mode
DTUNNEL (decode verified against the live ``data`` fixture; the
live gRPC call itself needs the server secret, so it is re-verified
only on the VPS after deploy).
"""
from __future__ import annotations

import json

if __package__:
    from .dtunnel import decode_catalog
else:
    from dtunnel import decode_catalog


def run(data: bytes) -> str:
    """Bridge entry point: bytes (the ``data`` string) -> JSON string."""
    return json.dumps(decode_catalog(data), ensure_ascii=False, indent=2) + "\n"
