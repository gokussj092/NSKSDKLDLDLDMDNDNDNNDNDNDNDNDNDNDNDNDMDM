#!/usr/bin/env python3
"""SP-DECODE server-side catalog decoder for MSY VPN Tunnel 11.4.1.

Bridge contract (see cloud/workers/python/catalog_vpn_bridge.py): the
broker downloads the live catalog (plain HTTP GET
http://servers.jk5.fun/servers.json via the dedicated downloader
downloadMsyVpn in cloud/web/lib/server-vpn-provider.mjs) and passes
the raw encrypted body here; run() returns the decrypted catalog as
one JSON string.

The body is a single Argon2id + AES-256-GCM envelope (key derived
from the SHA-256 of the app salt in libgojni.so); parse_catalog()
exposes it as {catalog_version, app_version, app_version_name,
app_url, app_msg, servers, configs}. The result JSON carries NO
download API: the endpoint lives in msyvpn.py (and the broker
PROVIDERS entry), never in the result.

VERIFIED_LIVE 2026-11-25: catalog_version 64, 3 servers, 18 configs.
"""
from __future__ import annotations

import json

if __package__:
    from .msyvpn import decrypt_raw_data, parse_catalog
else:
    from msyvpn import decrypt_raw_data, parse_catalog


def decode_catalog(data: bytes) -> dict:
    """Raw encrypted body (bytes) -> catalog dict."""
    return parse_catalog(json.loads(decrypt_raw_data(data)))


def run(data: bytes) -> str:
    """Bridge entry point: bytes -> JSON string."""
    return json.dumps(decode_catalog(data), ensure_ascii=False, indent=2) + "\n"
