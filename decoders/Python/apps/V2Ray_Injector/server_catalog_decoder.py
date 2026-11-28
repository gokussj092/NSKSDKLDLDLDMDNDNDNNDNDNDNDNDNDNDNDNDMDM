#!/usr/bin/env python3
"""V2Ray Injector 1.4.2 (tech.docnet.xraytunnel) - server catalog decoder.

Bridge contract (see cloud/workers/python/catalog_vpn_bridge.py): the
broker downloads the live catalog and passes the raw bytes here;
run() returns the decrypted catalog as one JSON string. No network
I/O in run().

Catalog (live, SecureConfigFetcher.kt):
  GET https://xraytunnel-config.admin6795.workers.dev/api/config
  Headers (exact): Accept: application/json
                   User-Agent: XrayTunnel/1.0
                   X-API-KEY: a112be46639d73d581813ecd2a382c6b
  Response JSON: {"servers": "<envelope>", "configs": "<envelope>",
                  "version": "1.0.0", "catalogSource": "manager",
                  "catalogReleaseId": "rel_...", "catalogSnapshotId": "cat_...",
                  "timestamp": <ms epoch>}
  Each envelope is base64(IV 12 B).base64(ciphertext + 16 B GCM tag),
  AES-256-GCM with the fixed 32-byte app key (see v2ray_injector.py).
  The /api/store endpoint on the same worker is only a community
  listing board; it carries no servers and is NOT a catalog.

The result is the decrypted catalog only (version, catalogSource,
catalogReleaseId, catalogSnapshotId, timestamp, servers, configs) -
no download APIs, no credentials, no keys. The X-API-KEY above is
the app's own fixed key shipped in the public APK (the broker sends
it as a header, exactly like the app); it is not an account
credential. Same precedent as JyFast's X-IGNIX-SIG header in the
broker (CAT 102 and earlier).

VERIFIED_LIVE 2026-11-28: Version 1.0.0, 1,233 servers, 63 configs
(08:28). Re-run 11:10 the same day: 1,216 servers, 63 configs, same
release/snapshot ids - the live feed churns (1,235 -> 1,233 -> 1,216
across the day); configs byte-identical, same release/snapshot.
The decoder reproduces the live catalog faithfully; byte-identical
to a fixed snapshot is impossible while the feed churns.
"""
from __future__ import annotations

import json

if __package__:
    from .v2ray_injector import decode_catalog_response
else:
    from v2ray_injector import decode_catalog_response


def run(data: bytes) -> str:
    """Bridge contract: raw worker-response bytes -> catalog JSON string.

    Raises ValueError on empty input, oversize input, a malformed
    response, an undecryptable envelope, or a catalog with no servers.
    Never performs network I/O and never emits download URLs,
    credentials or keys in the result.
    """
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise ValueError("empty V2Ray Injector response")
    if len(data) > 8 * 1024 * 1024:
        raise ValueError("V2Ray Injector response exceeds 8 MiB")
    catalog = decode_catalog_response(data)
    if not catalog.get("servers"):
        raise ValueError("V2Ray Injector catalog has no servers")
    return json.dumps(catalog, ensure_ascii=False, indent=2) + "\n"


def main() -> int:
    """Local verification CLI only: decode a saved worker response.

    Usage: server_catalog_decoder.py <response.json>
    (The broker fetches the live response; this CLI never downloads.)
    """
    import sys
    from pathlib import Path

    if len(sys.argv) != 2:
        print("usage: server_catalog_decoder.py <response.json>", file=sys.stderr)
        return 2
    data = Path(sys.argv[1]).read_bytes()
    try:
        print(run(data))
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
