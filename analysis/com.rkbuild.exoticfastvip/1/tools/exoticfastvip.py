#!/usr/bin/env python3
"""ExoticFast VIP (com.rkbuild.exoticfastvip, versionName "Rk1") catalog decoder.

Live catalog (verified 2026-11-27, Version 5.8):
    GET https://exoticfastvip.xyz/api/app?json=21dbd51eae6e8e810f71
    (plain HttpURLConnection GET, no special headers; f4/b.java)

Outer layer (n4/AbstractC2117a.b):
    1. strip ' ' and '\\n' from the response
    2. each pair of block characters is one byte (alphabet of 16):
       '▙▚▛▜▝▞▟▃▄▅▆▇█▉▊▐'
    3. those bytes are ASCII standard Base64 -> Base64-decode -> ciphertext
    4. AES-256-CBC, IV zero, PKCS7; key = SHA256("QHRlY2hub3JlMjQ=\\n" + HEX_UPPER(key))
       where "QHRlY2hub3JlMjQ=\\n" is Base64("@technore24") with Android DEFAULT '\\n'.
       Keys tried in order: "s2!0%20$" (live), fallback "rktrhsgasawrfv".

Field layer (OpenVPNClient.j0): XXTEA + standard Base64, key "s!02a"
    (padded with zeros to 16 bytes). See xxtea_j0.py.

Usage:
    python3 exoticfastvip.py                 # live download -> catalogo-*.json
    python3 exoticfastvip.py --file x.rj     # decrypt an offline-update file
    python3 exoticfastvip.py --file x.js     # (.rj / .js = same encrypted blob)
    python3 exoticfastvip.py --bundled       # decrypt the APK-bundled default
                                             # (res/0k.js, Version 1.0)

Outputs (written next to this script):
    catalogo-completo.json    full catalog, credentials intact (chat-only, never ZIP/Drive)
    catalogo-redactado.json   same data without IPs/hosts/passwords/UUIDs
"""
import argparse
import base64
import hashlib
import json
import os
import re
import sys
import urllib.request

from Crypto.Cipher import AES

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from xxtea_j0 import j0  # noqa: E402

CATALOG_URL = "https://exoticfastvip.xyz/api/app?json=21dbd51eae6e8e810f71"
OUTER_KEYS = ("s2!0%20$", "rktrhsgasawrfv")
BLOCK_ALPHABET = "▙▚▛▜▝▞▟▃▄▅▆▇█▉▊▐"

HERE = os.path.dirname(os.path.abspath(__file__))


def outer_decrypt(key: str, data: str) -> bytes:
    """AbstractC2117a.b(key, data): block-char layer + AES-256-CBC."""
    data = data.replace(" ", "").replace("\n", "")
    m = {c: i for i, c in enumerate(BLOCK_ALPHABET)}
    raw = bytes((m[data[i]] << 4) | m[data[i + 1]] for i in range(0, len(data) - 1, 2))
    ciphertext = base64.b64decode(raw)
    keymat = "QHRlY2hub3JlMjQ=\n" + key.encode("utf-8").hex().upper()
    aes_key = hashlib.sha256(keymat.encode("ascii")).digest()
    pt = AES.new(aes_key, AES.MODE_CBC, bytes(16)).decrypt(ciphertext)
    pad = pt[-1]
    if not (1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad):
        raise ValueError("bad PKCS7 padding (wrong outer key?)")
    return pt[:-pad]


def outer_decrypt_any(data: str) -> bytes:
    """Try the outer keys in order; fall back to the raw string (as the app does)."""
    last = None
    for key in OUTER_KEYS:
        try:
            return outer_decrypt(key, data)
        except Exception as exc:  # noqa: BLE001
            last = exc
    if data.lstrip().startswith("{"):
        return data.encode("utf-8")
    raise ValueError(f"outer decrypt failed with all keys: {last}")


# --- j0 field mapping (from OpenVPNClient.connect, lines ~1640-1868) ---
SERVER_J0_FIELDS = (
    "ServerIPHost", "ServerCloudFrontHost", "ServerHTTPHost",
    "Username", "Password", "Payload", "Nameserver", "PublicKey", "ServerEntry",
)
NETWORK_J0_FIELDS = ("Payload", "FrontQuery", "BackQuery", "SNIHost")


def decrypt_catalog(raw: dict) -> dict:
    """Apply j0 to every encrypted field of the catalog dict (in place, copy)."""
    cat = json.loads(json.dumps(raw))
    # Result JSONs never include the catalog download/auth APIs, only data.
    for api_key in ("update_api", "auth_api", "notice_api"):
        cat.pop(api_key, None)
    for srv in cat.get("Servers", []):
        for f in SERVER_J0_FIELDS:
            if isinstance(srv.get(f), str) and srv[f]:
                srv[f] = j0(srv[f])
    for net in cat.get("Networks", []) + cat.get("SSLNetworks", []):
        for f in NETWORK_J0_FIELDS:
            if isinstance(net.get(f), str) and net[f]:
                net[f] = j0(net[f])
        ps = net.get("ProxySettings")
        if isinstance(ps, dict) and isinstance(ps.get("Squid"), str) and ps["Squid"]:
            if ps["Squid"] != "[Default]":
                ps["Squid"] = j0(ps["Squid"])
    if isinstance(cat.get("OVPNCert"), str) and cat["OVPNCert"]:
        cat["OVPNCert"] = j0(cat["OVPNCert"])
    return cat


_VLESS_RE = re.compile(r"vless://[^@\s]+@[^?\s#]+")
_HOST_RE = re.compile(r"(host=|sni=)([^&\s#]+)")


def redact_text(s: str) -> str:
    """Strip credentials/hosts from a payload string (vless links, hysteria JSON)."""
    if not isinstance(s, str):
        return s
    s = _VLESS_RE.sub("vless://[REDACTED]@[REDACTED]", s)
    s = _HOST_RE.sub(lambda m: m.group(1) + "[REDACTED]", s)
    s = re.sub(r'"server"\s*:\s*"[^"]*"', '"server": "[REDACTED]"', s)
    s = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "[REDACTED-IP]", s)
    return s


def redact_catalog(cat: dict) -> dict:
    """Redacted copy: no IPs, hosts, usernames, passwords, UUIDs or certs."""
    red = json.loads(json.dumps(cat))
    for srv in red.get("Servers", []):
        for f in ("ServerIPHost", "ServerCloudFrontHost", "ServerHTTPHost",
                  "Username", "Password", "Nameserver", "PublicKey", "ServerEntry"):
            srv.pop(f, None)
        if isinstance(srv.get("Payload"), str):
            srv["Payload"] = redact_text(srv["Payload"])
    for net in red.get("Networks", []) + red.get("SSLNetworks", []):
        for f in ("Payload", "FrontQuery", "BackQuery", "SNIHost"):
            if isinstance(net.get(f), str):
                net[f] = redact_text(net[f])
    red.pop("OVPNCert", None)
    red.pop("XrayKey", None)
    return red


def summarize(cat: dict) -> dict:
    servers = cat.get("Servers", [])
    networks = cat.get("Networks", [])
    ssl = cat.get("SSLNetworks", [])
    free = [s for s in servers if str(s.get("Category", "")).upper() == "FREE"]
    srv_payloads = sum(1 for s in servers if s.get("Payload") and s["Payload"].strip("~!~ \n"))
    net_payloads = sum(1 for n in networks if n.get("Payload") and n["Payload"].strip(" \n"))
    return {
        "version": cat.get("Version"),
        "servers_total": len(servers),
        "servers_free": len(free),
        "servers_premium": sum(1 for s in servers if str(s.get("Category", "")).upper() == "PREMIUM"),
        "server_payloads_nonempty": srv_payloads,
        "networks_total": len(networks),
        "ssl_networks_total": len(ssl),
        "network_payloads_nonempty": net_payloads,
    }


def fetch_live() -> str:
    req = urllib.request.Request(CATALOG_URL, method="GET")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


def main() -> int:
    ap = argparse.ArgumentParser(description="ExoticFast VIP catalog decoder")
    ap.add_argument("--file", help="offline-update file (.rj/.js) to decrypt instead of live")
    ap.add_argument("--bundled", action="store_true",
                    help="decrypt the APK-bundled default catalog (apk/res/0k.js)")
    ap.add_argument("--outdir", default=HERE)
    args = ap.parse_args()

    if args.bundled:
        with open(os.path.join(HERE, "apk", "res", "0k.js"), encoding="utf-8") as fh:
            raw_text = fh.read()
        tag = "bundled"
    elif args.file:
        with open(args.file, encoding="utf-8", errors="replace") as fh:
            raw_text = fh.read()
        tag = "file"
    else:
        raw_text = fetch_live()
        tag = "live"

    plain = outer_decrypt_any(raw_text)
    raw_cat = json.loads(plain)
    cat = decrypt_catalog(raw_cat)

    complete_path = os.path.join(args.outdir, "catalogo-completo.json")
    redacted_path = os.path.join(args.outdir, "catalogo-redactado.json")
    with open(complete_path, "w", encoding="utf-8") as fh:
        json.dump(cat, fh, ensure_ascii=False, indent=2)
    with open(redacted_path, "w", encoding="utf-8") as fh:
        json.dump(redact_catalog(cat), fh, ensure_ascii=False, indent=2)

    s = summarize(cat)
    print(f"source: {tag}  url: {CATALOG_URL if tag == 'live' else '-'}")
    print(f"Version: {s['version']}")
    print(f"Servers: {s['servers_total']} total, {s['servers_free']} FREE, "
          f"{s['servers_premium']} PREMIUM, {s['server_payloads_nonempty']} with payload")
    print(f"Networks: {s['networks_total']}  SSLNetworks: {s['ssl_networks_total']}  "
          f"network payloads: {s['network_payloads_nonempty']}")
    print(f"wrote {complete_path}")
    print(f"wrote {redacted_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
