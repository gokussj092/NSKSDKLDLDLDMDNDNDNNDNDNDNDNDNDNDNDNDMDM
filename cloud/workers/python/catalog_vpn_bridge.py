#!/usr/bin/env python3
"""Private, offline, allowlisted C8 VPN catalog decoder bridge."""
from __future__ import annotations
import importlib
import json
import sys
from pathlib import Path

PROVIDERS = {
    "24clan-green": "decoders.Python.apps.24clan_VPN_Green.24clan_VPN_Green",
    "hx-tunnel": "decoders.Python.apps.HX_Tunnel_VPN.HX_Tunnel_VPN",
    "mkk-hyper": "decoders.Python.apps.MKK_Hyper_VPN.MKK_Hyper_VPN",
    "my-tunnel-proxy": "decoders.Python.apps.My_Tunnel_Proxy.server_catalog_decoder",
    "robust-tunnel": "decoders.Python.apps.Robust_Tunnel_VPN.server_catalog_decoder",
    # Offline only until the live endpoint and original icon meet public gates.
    "royal-tunnel": "decoders.Python.apps.Royal_Tunnel_VPN.server_catalog_decoder",
}

def decode(provider_id: str, payload: bytes) -> str:
    module_name = PROVIDERS.get(provider_id)
    if module_name is None:
        raise ValueError("Unsupported provider")
    module = importlib.import_module(module_name)
    result = module.run(payload)
    if not isinstance(result, str) or not result.strip():
        raise ValueError("Unable to decode complete catalog")
    # Reject malformed and incomplete catalogs, preserve original entire JSON.
    value = json.loads(result)
    if not isinstance(value, (dict, list)) or not value:
        raise ValueError("Invalid catalog result")
    return result

def main() -> int:
    if len(sys.argv)!=3:
        return 2
    try:
        data=Path(sys.argv[2]).read_bytes()
        if not data or len(data)>8*1024*1024:
            return 1
        rendered=decode(sys.argv[1],data)
    except (ValueError, OSError, ImportError, RecursionError):
        return 1
    sys.stdout.write(rendered)
    return 0

if __name__=="__main__":
    raise SystemExit(main())
