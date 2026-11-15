#!/usr/bin/env python3
"""PUKANG VPN catalog decoder for SP-DECODE.

App: PUKANG VPN, com.pukangvpn.th, version 8.7 (versionCode 87, minSdk 32).
Catalog URL (from libapi-pukang.so, MainDetail.a() native):
    https://pukangvpn.xyz/pukangvpn/Config.json
Request (exact, as the app does it with OkHttp 5.3.2):
    GET <url>
    User-Agent: okhttp/5.3.2
    Accept-Encoding: identity
No authentication, no query parameters, no custom headers.

Envelope: one line of standard Base64 -> modified XXTEA
(delta 0x2E0BA747, last word = plaintext length, key = first 16 bytes
of the format key "pukangvpn270@" zero-padded) -> JSON:
    {"Version": "144", "Message": "...", "Servers": [...],
     "Networks": [...], "setOpenVPN": "<base64>"}
Server and network string fields that are Base64 in the catalog are
decoded in place (same field lists as the sister app KHAM VPN):
  servers:  ServerIP, Cloudfront, NameServer, PublicKey, ServerDNS,
            ProxyIP, Username, Password, setOpenVPN, V2Ray, UDPConfig
  networks: Sni, ServerDNS, Payload, SquidProxy
  top level: setOpenVPN
UDPConfig decodes to a JSON object (obfs/auth) when it parses as JSON.

The app saves the downloaded catalog (re-encrypted with the same
envelope) as filesDir/profile.json; see PUKANG_VPN_archivos.py.

Live test (2026-11-14): HTTP 200, 60,588 bytes -> Version 144,
17 servers, 19 networks, 16 networks with a non-empty Payload.
The catalog carries no free/premium/VIP marker on any server.

Pure Python standard library. No credentials are printed by --summary;
--decoded prints the full catalog including server credentials, exactly
as the app itself shows them after decoding.
"""

import argparse
import base64
import json
import sys
import urllib.request

CATALOG_URL = "https://pukangvpn.xyz/pukangvpn/Config.json"
FORMAT_KEY = "pukangvpn270@"
USER_AGENT = "okhttp/5.3.2"

MASK = 0xFFFFFFFF
DELTA = 0x2E0BA747

SERVER_FIELDS = (
    "ServerIP", "Cloudfront", "NameServer", "PublicKey", "ServerDNS",
    "ProxyIP", "Username", "Password", "setOpenVPN", "V2Ray", "UDPConfig",
)
NETWORK_FIELDS = ("Sni", "ServerDNS", "Payload", "SquidProxy")


# ---------------------------------------------------------------- XXTEA
def _mx(sum_, y, z, p, e, k):
    # MX function from ea2.b in the app (all arithmetic mod 2**32).
    a = ((sum_ ^ y) + (k[(p & 3) ^ e] ^ z)) & MASK
    b = (((z >> 5) ^ ((y << 2) & MASK))
         + ((y >> 3) ^ ((z << 4) & MASK))) & MASK
    return (a ^ b) & MASK


def _to_words(data, include_length):
    n = (len(data) + 3) // 4
    words = [0] * (n + (1 if include_length else 0))
    for i, b in enumerate(data):
        words[i >> 2] |= b << ((i & 3) << 3)
    if include_length:
        words[n] = len(data)
    return words


def _to_bytes(words, include_length):
    n = len(words) << 2
    if include_length:
        m = words[-1]
        if m < n - 7 or m > n - 4:
            return None
        n = m
    out = bytearray(n)
    for i in range(n):
        out[i] = (words[i >> 2] >> ((i & 3) << 3)) & 0xFF
    return bytes(out)


def _key_words(key):
    kb = key.encode("utf-8")
    if len(kb) != 16:
        kb = (kb + b"\x00" * 16)[:16]
    return _to_words(kb, False)


def xxtea_decrypt(data, key=FORMAT_KEY):
    """Modified XXTEA decrypt (ea2.i in the app). Returns bytes or None."""
    v = _to_words(data, False)
    k = _key_words(key)
    n = len(v)
    if n < 2:
        return data
    rounds = 6 + 52 // n
    sum_ = (rounds * DELTA) & MASK
    y = v[0]
    while sum_ != 0:
        e = (sum_ >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            y = (v[p] - _mx(sum_, y, z, p, e, k)) & MASK
            v[p] = y
        z = v[n - 1]
        y = (v[0] - _mx(sum_, y, z, 0, e, k)) & MASK
        v[0] = y
        sum_ = (sum_ - DELTA) & MASK
    return _to_bytes(v, True)


def xxtea_encrypt(data, key=FORMAT_KEY):
    """Modified XXTEA encrypt (ea2.j in the app)."""
    v = _to_words(data, True)
    k = _key_words(key)
    n = len(v)
    if n < 2:
        return data
    rounds = 6 + 52 // n
    sum_ = 0
    z = v[n - 1]
    for _ in range(rounds):
        sum_ = (sum_ + DELTA) & MASK
        e = (sum_ >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            z = (v[p] + _mx(sum_, y, z, p, e, k)) & MASK
            v[p] = z
        y = v[0]
        z = (v[n - 1] + _mx(sum_, y, z, n - 1, e, k)) & MASK
        v[n - 1] = z
    return _to_bytes(v, False)


# ---------------------------------------------------------------- catalog
def _b64_text(value):
    """Base64-decode a catalog string field to UTF-8 text (or None)."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except Exception:
        return None


def decode_fields(catalog):
    """Decode the Base64 string fields of a parsed catalog in place."""
    for server in catalog.get("Servers") or []:
        if not isinstance(server, dict):
            continue
        for field in SERVER_FIELDS:
            text = _b64_text(server.get(field))
            if text is None:
                continue
            if field == "UDPConfig":
                try:
                    server[field] = json.loads(text)
                    continue
                except Exception:
                    pass
            server[field] = text
    for net in catalog.get("Networks") or []:
        if not isinstance(net, dict):
            continue
        for field in NETWORK_FIELDS:
            text = _b64_text(net.get(field))
            if text is not None:
                net[field] = text
    text = _b64_text(catalog.get("setOpenVPN"))
    if text is not None:
        catalog["setOpenVPN"] = text
    return catalog


def decode(raw):
    """Decode a raw catalog body (bytes or str) to a dict.

    Accepts the Base64 envelope exactly as downloaded, or the raw
    XXTEA ciphertext bytes. Raises ValueError on failure.
    """
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", "ignore").strip()
    else:
        text = raw.strip()
    try:
        blob = base64.b64decode(text, validate=True)
    except Exception:
        blob = text.encode("utf-8") if isinstance(text, str) else text
        if not blob:
            raise ValueError("empty catalog body")
    plain = xxtea_decrypt(blob)
    if plain is None:
        raise ValueError("XXTEA decrypt failed (bad length word)")
    try:
        catalog = json.loads(plain.decode("utf-8"), strict=False)
    except Exception as exc:
        raise ValueError("decrypted body is not JSON: %s" % exc)
    if not isinstance(catalog, dict):
        raise ValueError("decrypted body is not a JSON object")
    return decode_fields(catalog)


def fetch_catalog(url=CATALOG_URL, timeout=30):
    """Download the catalog exactly as the app does. Returns raw bytes."""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept-Encoding": "identity",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def summarize(catalog):
    servers = catalog.get("Servers") or []
    networks = catalog.get("Networks") or []
    with_payload = sum(
        1 for n in networks
        if isinstance(n, dict) and n.get("Payload")
    )
    return {
        "Version": catalog.get("Version"),
        "Message": catalog.get("Message"),
        "servers": len(servers),
        "networks": len(networks),
        "networks_with_payload": with_payload,
    }


def self_test():
    """Round-trip test on a synthetic catalog + the live sample body."""
    sample = {
        "Version": "144",
        "Message": "test",
        "Servers": [
            {
                "ServerName": "Server-01",
                "ServerFlag": "sg",
                "ServerIP": base64.b64encode(b"nn01.pukangvpn.xyz").decode(),
                "Username": base64.b64encode(b"user").decode(),
                "Password": base64.b64encode(b"pass").decode(),
            }
        ],
        "Networks": [
            {
                "PayloadName": "Global network",
                "Payload": base64.b64encode(b"GET / HTTP/1.1").decode(),
            }
        ],
        "setOpenVPN": base64.b64encode(b"client\n").decode(),
    }
    blob = base64.b64encode(
        xxtea_encrypt(json.dumps(sample).encode("utf-8"))
    ).decode()
    decoded = decode(blob)
    assert decoded["Version"] == "144", decoded
    assert decoded["Servers"][0]["ServerIP"] == "nn01.pukangvpn.xyz"
    assert decoded["Servers"][0]["Username"] == "user"
    assert decoded["Networks"][0]["Payload"] == "GET / HTTP/1.1"
    assert decoded["setOpenVPN"] == "client\n"
    # live sample body (ciphertext captured 2026-11-14, Version 144)
    try:
        with open("catalog_sample.b64", "rb") as fh:
            sample_blob = fh.read()
    except OSError:
        import os
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "catalog_sample.b64"), "rb") as fh:
            sample_blob = fh.read()
    live = decode(sample_blob)
    assert live["Version"] == "144", live.get("Version")
    assert len(live["Servers"]) == 17, len(live["Servers"])
    assert len(live["Networks"]) == 19, len(live["Networks"])
    return True


def run():
    ap = argparse.ArgumentParser(
        description="PUKANG VPN catalog decoder (SP-DECODE)."
    )
    ap.add_argument("--url", action="store_true",
                    help="download the live catalog from %s" % CATALOG_URL)
    ap.add_argument("--file", metavar="PATH",
                    help="decode a saved catalog blob / profile.json file")
    ap.add_argument("--asset", action="store_true",
                    help="decode the included catalog_sample.b64")
    ap.add_argument("--self-test", action="store_true",
                    help="run the built-in self-test and exit")
    ap.add_argument("-o", "--output", metavar="PATH",
                    help="write the decoded catalog JSON to PATH")
    ap.add_argument("--summary", action="store_true",
                    help="print only the summary (no credentials)")
    ap.add_argument("--decoded", action="store_true",
                    help="print the full decoded catalog JSON")
    args = ap.parse_args()

    if args.self_test:
        ok = self_test()
        print("self-test: PASS" if ok else "self-test: FAIL")
        return 0 if ok else 1

    if args.url:
        raw = fetch_catalog()
    elif args.file:
        with open(args.file, "rb") as fh:
            raw = fh.read()
    elif args.asset:
        import os
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "catalog_sample.b64"), "rb") as fh:
            raw = fh.read()
    else:
        ap.error("nothing to do: pass --url, --file, --asset or --self-test")

    try:
        catalog = decode(raw)
    except ValueError as exc:
        print("DECODE_FAILED: %s" % exc, file=sys.stderr)
        return 2

    summary = summarize(catalog)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(catalog, fh, ensure_ascii=False, indent=2)
    if args.decoded:
        print(json.dumps(catalog, ensure_ascii=False, indent=2))
    else:
        print("Version: %s" % summary["Version"])
        print("Servers: %d" % summary["servers"])
        print("Networks: %d (%d with Payload)"
              % (summary["networks"], summary["networks_with_payload"]))
        if summary["Message"]:
            print("Message: %s" % summary["Message"])
    if args.summary and not args.decoded:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(run())
