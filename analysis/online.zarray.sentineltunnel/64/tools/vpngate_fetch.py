#!/usr/bin/env python3
"""Verification helper: fetch the live VPNGate feed (HTTPS only, as the
app does) and parse it with the staged server_catalog_decoder.

This is a verification tool, not the broker path: the broker fetches the
feed itself and hands the bytes to server_catalog_decoder.run(). The
analyst script's plain-HTTP fallback (a workaround for this VM's egress
proxy resetting HTTPS) is deliberately NOT reproduced here or in the
broker: production fetches use HTTPS only.

Usage:
  vpngate_fetch.py [--out feed.csv] [--expect-min N]
Exit 0 when the feed parses to >= --expect-min servers (default 1).
Prints the server count and per-country breakdown; never prints IPs,
configs or credentials.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] /
                       "decoders" / "Python" / "apps" / "Sentinel_Tunnel"))
from server_catalog_decoder import parse_vpngate_csv  # noqa: E402

VPNGATE_URL = "https://www.vpngate.net/api/iphone/"
USER_AGENT = "SentinelTunnel/2.5"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", help="save the raw feed CSV here")
    p.add_argument("--expect-min", type=int, default=1)
    args = p.parse_args()
    req = urllib.request.Request(
        VPNGATE_URL,
        headers={"User-Agent": USER_AGENT,
                 "Accept": "text/csv, text/plain, */*"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            if resp.status != 200:
                print("VPNGate HTTP %s" % resp.status, file=sys.stderr)
                return 1
            text = resp.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 - report, do not invent data
        print("VPNGate fetch failed: %r" % (exc,), file=sys.stderr)
        return 1
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    try:
        servers = parse_vpngate_csv(text)
    except ValueError as exc:
        print("VPNGate parse failed: %s" % (exc,), file=sys.stderr)
        return 1
    countries: dict[str, int] = {}
    for server in servers:
        countries[server["countryShort"]] = \
            countries.get(server["countryShort"], 0) + 1
    print("VPNGate servers: %d" % len(servers))
    print("countries: %s" % json.dumps(countries, sort_keys=True))
    if len(servers) < args.expect_min:
        print("fewer than --expect-min %d servers" % args.expect_min,
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
