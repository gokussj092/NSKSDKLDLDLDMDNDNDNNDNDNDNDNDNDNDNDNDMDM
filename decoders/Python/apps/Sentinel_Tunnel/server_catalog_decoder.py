#!/usr/bin/env python3
"""Sentinel Tunnel 4.0.0 (online.zarray.sentineltunnel) - VPNGate catalog decoder.

Offline bridge entry point: run(bytes) -> str.

The app's OWN VPS catalog (api.zarray.online:2096, 9 types) is BLOCKED: the
v2 API answers HTTP 401 {"error":"unauthorized"} without a valid Firebase
App Check token (Play Integrity, minted on a real device running the app).
No broker, token or key for that API is invented here, and no VPS key
material lives in this file. The VPS catalog stays undelivered (PARTIAL)
until a real App Check token exists.

The LIVE catalog this decoder serves is the public VPNGate feed, which is
the app's own free-server browser (VPNGateRepository in the app fetches
exactly this feed and shows it as the free servers). The broker (not this
module) fetches the feed; this module only parses the bytes the broker
hands it and renders the catalog JSON. The result contains catalog data
only - no download APIs, no credentials, no keys.

VPNGate feed (public, no auth; broker fetches it over HTTPS):
    GET https://www.vpngate.net/api/iphone/
    User-Agent: SentinelTunnel/2.5
CSV columns: HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,
NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,
OpenVPN_ConfigData_Base64. Protocol/port are extracted from the decoded
.ovpn config ("proto udp" -> UDP else TCP; "remote host port" -> port),
mirroring VPNGateRepository.parseCsv/parseServerLine.

Live verification 2026-11-27: 98 servers (JP 50, KR 32, TH 7, RU 3,
VN 2, US 1, RO 1, PE 1, MM 1). A re-run the same day returned 95
servers - the feed changes as volunteer servers come and go; the count
is live data, not a fixed number. One row in the re-run feed carries
Ping "-" (unmeasured), which crashed the analyst's strict int() parser;
this parser tolerates non-numeric numeric fields (default -1) and skips
only rows whose .ovpn config is missing or undecodable.

Source method: ~/workspace/batch15-work/sentinel-tunnel/
sentinel_tunnel_catalog.py (parse_vpngate_csv), reimplemented here
offline with the tolerant-int fix. No network access in run().
"""
from __future__ import annotations

import base64
import json
import re

MAX_BYTES = 8 * 1024 * 1024

VPNGATE_COLUMNS = (
    "hostName", "ip", "score", "ping", "speed", "countryLong",
    "countryShort", "numVpnSessions", "uptime", "totalUsers",
    "totalTraffic", "logType", "operator", "message",
)


def _int(value: str, default: int = -1) -> int:
    """Strict ints crash the feed: VPNGate emits "-" for unmeasured Ping."""
    try:
        return int((value or "").strip())
    except (ValueError, TypeError):
        return default


def _proto_port(ovpn: str) -> tuple[str, int]:
    proto, port = "TCP", 443
    for line in ovpn.splitlines():
        line = line.strip()
        if line.startswith("proto "):
            if "udp" in line.lower():
                proto = "UDP"
        elif line.startswith("remote ") and not line.startswith("remote-"):
            toks = re.split(r"\s+", line)
            if len(toks) > 2:
                try:
                    port = int(toks[2])
                except ValueError:
                    pass
            if len(toks) > 3 and toks[3].lower() in ("udp", "tcp"):
                proto = toks[3].upper()
    return proto, port


def parse_vpngate_csv(csv_text: str) -> list[dict]:
    """Parse the VPNGate CSV bytes (as text) into server dicts."""
    lines = csv_text.splitlines()
    hdr = next((i for i, line in enumerate(lines)
                if line.startswith("#HostName")), None)
    if hdr is None:
        raise ValueError("VPNGate feed has no #HostName header")
    servers: list[dict] = []
    for line in lines[hdr + 1:]:
        line = line.strip()
        if not line or line.startswith("*") or line.startswith("#"):
            continue
        parts = line.split(",", 14)
        if len(parts) < 15 or not parts[14].strip():
            continue
        try:
            ovpn = base64.b64decode(parts[14]).decode("utf-8", "replace")
        except Exception:
            continue
        proto, port = _proto_port(ovpn)
        server = {
            "hostName": parts[0].strip(),
            "ip": parts[1].strip(),
            "score": _int(parts[2], 0),
            "ping": _int(parts[3], -1),
            "speed": _int(parts[4], 0),
            "countryLong": parts[5].strip(),
            "countryShort": parts[6].strip(),
            "numVpnSessions": _int(parts[7], 0),
            "uptime": _int(parts[8], 0),
            "totalUsers": _int(parts[9], 0),
            "totalTraffic": _int(parts[10], 0),
            "logType": parts[11].strip(),
            "operator": parts[12].strip(),
            "message": parts[13].strip(),
            "protocol": proto,
            "port": port,
            "ovpnConfig": ovpn,
        }
        servers.append(server)
    return servers


def run(data: bytes) -> str:
    """Bridge contract: VPNGate CSV bytes -> catalog JSON string.

    Raises ValueError on empty input, oversize input, a missing header,
    or a feed with zero usable servers. Never performs network I/O and
    never emits download URLs, credentials or keys in the result.
    """
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise ValueError("empty VPNGate feed")
    if len(data) > MAX_BYTES:
        raise ValueError("VPNGate feed exceeds 8 MiB")
    servers = parse_vpngate_csv(data.decode("utf-8", "replace"))
    if not servers:
        raise ValueError("VPNGate feed contains no usable servers")
    countries: dict[str, int] = {}
    for server in servers:
        countries[server["countryShort"]] = \
            countries.get(server["countryShort"], 0) + 1
    catalog = {
        "app": "Sentinel Tunnel",
        "package": "online.zarray.sentineltunnel",
        "version": "4.0.0",
        "versionCode": 64,
        "source": "vpngate",
        "sourceNote": "Public VPNGate feed: the app's own free-server "
                      "browser (VPNGateRepository). The app's own VPS "
                      "catalog is blocked (HTTP 401, Firebase App Check "
                      "token required) and is not part of this result.",
        "serverCount": len(servers),
        "countries": countries,
        "servers": servers,
    }
    return json.dumps(catalog, ensure_ascii=False, indent=2)


def main() -> int:
    """Local verification CLI only: parse a saved feed file.

    Usage: server_catalog_decoder.py <feed.csv>
    (The broker fetches the live feed; this CLI never downloads.)
    """
    import sys
    from pathlib import Path

    if len(sys.argv) != 2:
        print("usage: server_catalog_decoder.py <feed.csv>", file=sys.stderr)
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
