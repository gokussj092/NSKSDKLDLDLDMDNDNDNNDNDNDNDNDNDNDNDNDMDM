#!/usr/bin/env python3
"""DGM Tunnel 15.11.2026 (com.dgmtunnel.app) - rotating public-feed catalog decoder.

Bridge contract (see cloud/workers/python/catalog_vpn_bridge.py): the
broker downloads the live feed and passes the raw bytes here; run()
returns the decoded catalog as one JSON string. No network I/O in run().

Feed (live, FreeServerCatalog.fetch):
  GET https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt
  User-Agent: DGMTunnel/1.5, 15 s timeouts, no redirect following.
  Plain text, no encryption. The app parses the first 500 profiles,
  filters (no SSH, no proxy), dedupes by protocol:server:port:uuid
  and takes the first 40.

ROTATING FEED, NO CATALOG VERSION: the feed is a third-party list
that changes daily, so a later re-fetch returns a different 40.
The snapshot carries NO version number and no fetch timestamp;
the result holds only the app identification and the profiles.
This is the app's own behaviour, not an error. Precedent:
Sentinel Tunnel (CAT 102) is also a public rotating feed
(VPNGate) served as a card.

The result is the decoded catalog only (app, package, versionName,
versionCode, profiles) - no download APIs, no credentials, no keys.

VERIFIED_LIVE 2026-11-28: feed 8,880 lines / 8,873 entries,
500 parsed, 57 rejected, 40 profiles, all Shadowsocks (10:05 UTC).
Re-run 11:12 UTC: identical 40 profiles (feed unchanged between
the two runs).
"""
from __future__ import annotations

import json

if __package__:
    from .dgm_tunnel import MAX_BYTES, decode_feed_catalog
else:
    from dgm_tunnel import MAX_BYTES, decode_feed_catalog


def run(data: bytes) -> str:
    """Bridge contract: feed bytes -> catalog JSON string.

    Raises ValueError on empty input, oversize input, undecodable
    text, or a feed that yields no profiles. Never performs network
    I/O and never emits download URLs, credentials or keys in the
    result.
    """
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise ValueError("empty DGM feed")
    if len(data) > MAX_BYTES:
        raise ValueError("DGM feed exceeds 4 MiB")
    doc = decode_feed_catalog(data)
    if not doc.get("profiles"):
        raise ValueError("DGM feed produced no profiles")
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"


def main() -> int:
    """Local verification CLI only: decode a saved feed file.

    Usage: server_catalog_decoder.py <feed.txt>
    (The broker fetches the live feed; this CLI never downloads.)
    """
    import sys
    from pathlib import Path

    if len(sys.argv) != 2:
        print("usage: server_catalog_decoder.py <feed.txt>", file=sys.stderr)
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
