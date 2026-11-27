#!/usr/bin/env python3
"""ThaiVPN Connect 2.4 (com.openvpnservice.thaivpnconnect, versionCode 24)
Live catalog + profile.json file decoder.

Method (verified against the APK, 2026-11-27):
  * Catalog URL (MainDetail.a(), from native libapi-thaivpn.so):
        GET https://thaivapp.my.id/app/thvpn.json
    Plain GET, no headers, no auth. The server answers HTTP 200 with a
    single-line Base64 blob (Last-Modified: Wed, 25 Nov 2026 06:58:09 GMT).
  * Outer layer: XXTEA (Q0.f.o / Q0.f.q in the app) with delta 772515655,
    key = MainDetail.b() = "aluya20" (from libapi-thaivpn.so), padded with
    zero bytes to 16. Base64-decoded blob -> XXTEA-decrypt -> JSON with
    keys Version / Message / Servers[] / Networks[] / setOpenVPN.
  * Inner layer: several fields are Base64 (H0.y.E = standard Base64
    decode, used by the app at runtime, e.g. y.E(ServerIP) to build the
    ping URL http://<ServerIP>:82/server/online_app.json). Those fields
    are decoded below; every other field is stored in plain text.
    - Servers: ServerIP, NameServer, ServerDNS, Username, Password,
      PublicKey, UDPConfig (decodes to JSON), setOpenVPN (decodes to an
      .ovpn config text), V2Ray (Base64 when present).
    - Networks: Sni, Payload, SquidProxy, ServerDNS.
    - Top level: setOpenVPN (Base64 .ovpn config text).
  * File format: the app stores the same encrypted JSON in its private
    file "profile.json" (written with y.z = XXTEA-encrypt + Base64 after
    each catalog update, read back by j3/C1855a.a()). This script decodes
    such a profile.json file too, and can re-encrypt (--encrypt).
  * Text links: the app has NO custom scheme. Its V2Ray part
    (V2RayConfigManager) only handles the standard vmess://, vless://,
    trojan:// and ss:// links, which generic V2Ray decoders already cover.

Usage:
    python3 thaivpn.py --catalog [--out catalogo-completo.json]
                       [--redacted catalogo-redactado.json]
    python3 thaivpn.py --file profile.json [--out out.json]
    python3 thaivpn.py --encrypt catalog.json --out profile.json
    python3 thaivpn.py --check-catalog   (fetch + decrypt + verify no
                                          encoded value remains)

Python 3, standard library only.
"""
import argparse
import base64
import copy
import json
import re
import sys
import urllib.request

CATALOG_URL = "https://thaivapp.my.id/app/thvpn.json"
PING_URL = "https://thaivapp.my.id/kuay/ping.json"  # MainDetail.c(), server-online list (not the catalog)
KEY = b"aluya20"  # MainDetail.b(), from lib/arm64-v8a/libapi-thaivpn.so

_M = 0xFFFFFFFF
_DELTA = 772515655  # XXTEA delta used by the app (Q0.f.o / Q0.f.q)

# Fields that the app stores Base64-encoded (decoded with H0.y.E at runtime).
B64_SERVER_FIELDS = ("ServerIP", "NameServer", "ServerDNS", "Username",
                     "Password", "PublicKey", "UDPConfig", "setOpenVPN",
                     "V2Ray")
B64_NETWORK_FIELDS = ("Sni", "Payload", "SquidProxy", "ServerDNS")
B64_TOP_FIELDS = ("setOpenVPN",)

# Fields redacted in the redacted catalog (server IPs/hosts, credentials).
REDACT_SERVER_FIELDS = ("ServerIP", "NameServer", "ServerDNS", "Username",
                        "Password", "PublicKey")
REDACT_NETWORK_FIELDS = ("SquidProxy", "ServerDNS")
REDACTED = "***REDACTED***"


def _mx(s, y, z, p, e, k):
    return (((s ^ y) + (k[(p & 3) ^ e] ^ z))
            ^ (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))) & _M


def _to_ints(data, include_len):
    n = (len(data) + 3) // 4
    v = [0] * (n + (1 if include_len else 0))
    for i, b in enumerate(data):
        v[i >> 2] |= b << ((i & 3) << 3)
    if include_len:
        v[n] = len(data)
    return v


def _to_bytes(v, include_len):
    n = len(v) << 2
    if include_len:
        m = v[-1]
        if m < n - 7 or m > n - 4:
            return None
        n = m
    return bytes((v[i >> 2] >> ((i & 3) << 3)) & 0xFF for i in range(n))


def _key_ints(key):
    kk = bytearray(16)
    kk[:min(len(key), 16)] = key[:16]
    return _to_ints(bytes(kk), False)


def xxtea_decrypt(data, key=KEY):
    """XXTEA decrypt exactly as Q0.f.o (returns None on bad length)."""
    if not data:
        return data
    v = _to_ints(data, False)
    k = _key_ints(key)
    n = len(v)
    rounds = (52 // n) + 6
    y = v[0]
    s = (rounds * _DELTA) & _M
    while s != 0:
        e = (s >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            y = (v[p] - _mx(s, y, z, p, e, k)) & _M
            v[p] = y
        z = v[n - 1]
        y = (v[0] - _mx(s, y, z, 0, e, k)) & _M
        v[0] = y
        s = (s - _DELTA) & _M
    return _to_bytes(v, True)


def xxtea_encrypt(data, key=KEY):
    """XXTEA encrypt exactly as Q0.f.q (inverse of xxtea_decrypt)."""
    if not data:
        return data
    v = _to_ints(data, True)
    k = _key_ints(key)
    n = len(v)
    rounds = (52 // n) + 6
    z = v[n - 1]
    s = 0
    for _ in range(rounds):
        s = (s + _DELTA) & _M
        e = (s >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            z = (v[p] + _mx(s, y, z, p, e, k)) & _M
            v[p] = z
        y = v[0]
        z = (v[n - 1] + _mx(s, y, z, n - 1, e, k)) & _M
        v[n - 1] = z
    return _to_bytes(v, False)


def _b64decode_text(value):
    """Decode a Base64 string to UTF-8 text; None if not decodable text."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        raw = base64.b64decode("".join(value.split()), validate=False)
        text = raw.decode("utf-8")
    except Exception:
        return None
    if not text or not all(c.isprintable() or c in "\r\n\t" for c in text):
        return None
    return text


def _decode_field(value):
    """Decode one inner-Base64 field; JSON text becomes a parsed object."""
    text = _b64decode_text(value)
    if text is None:
        return value
    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            return json.loads(stripped)
        except Exception:
            pass
    return text


def decode_catalog(raw_catalog):
    """Decode every inner-Base64 field of an already XXTEA-decrypted catalog."""
    cat = copy.deepcopy(raw_catalog)
    for srv in cat.get("Servers", []):
        for field in B64_SERVER_FIELDS:
            if srv.get(field):
                srv[field] = _decode_field(srv[field])
    for net in cat.get("Networks", []):
        for field in B64_NETWORK_FIELDS:
            if net.get(field):
                net[field] = _decode_field(net[field])
    for field in B64_TOP_FIELDS:
        if cat.get(field):
            cat[field] = _decode_field(cat[field])
    return cat


def decrypt_blob(blob_b64):
    """Outer layer: Base64 + XXTEA -> parsed catalog JSON (still inner-encoded)."""
    data = base64.b64decode("".join(blob_b64.split()))
    plain = xxtea_decrypt(data)
    if plain is None:
        raise ValueError("XXTEA decrypt failed (length check)")
    return json.loads(plain.decode("utf-8"))


def encrypt_blob(catalog):
    """Inverse of decrypt_blob: catalog dict -> Base64(XXTEA(JSON))."""
    plain = json.dumps(catalog, ensure_ascii=False,
                       separators=(",", ":")).encode("utf-8")
    return base64.b64encode(xxtea_encrypt(plain)).decode("ascii")


def fetch_catalog_raw(url=CATALOG_URL, timeout=30):
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8")


def fetch_catalog(url=CATALOG_URL):
    """Download the live catalog and fully decode it (outer + inner layers)."""
    return decode_catalog(decrypt_blob(fetch_catalog_raw(url)))


def decode_profile_file(path):
    """Decode an app profile.json file (Base64 + XXTEA, same as catalog)."""
    with open(path, "r", encoding="utf-8") as fh:
        blob = fh.read()
    return decode_catalog(decrypt_blob(blob))


def redact_catalog(catalog):
    """Copy of the catalog with server IPs/hosts and credentials removed."""
    cat = copy.deepcopy(catalog)
    for srv in cat.get("Servers", []):
        for field in REDACT_SERVER_FIELDS:
            if srv.get(field):
                srv[field] = REDACTED
        udp = srv.get("UDPConfig")
        if isinstance(udp, dict) and udp.get("auth_str"):
            udp["auth_str"] = REDACTED
    for net in cat.get("Networks", []):
        for field in REDACT_NETWORK_FIELDS:
            if net.get(field):
                net[field] = REDACTED
    return cat


_B64_LIKE = re.compile(r"^[A-Za-z0-9+/=\s]{16,}$")


def find_leftover_encoded(catalog):
    """Return paths of string values that still look Base64-encoded.

    A value counts as leftover only if it is long, Base64-shaped, and
    decodes to printable UTF-8 text (short plain values such as ports,
    flags or protocol names are not Base64 and never match this).
    """
    leftovers = []

    def walk(node, path):
        if isinstance(node, dict):
            for key, val in node.items():
                walk(val, f"{path}.{key}")
        elif isinstance(node, list):
            for idx, val in enumerate(node):
                walk(val, f"{path}[{idx}]")
        elif isinstance(node, str):
            stripped = node.strip()
            if (len(stripped) >= 16 and _B64_LIKE.match(node)
                    and _b64decode_text(node) is not None
                    and node not in (REDACTED,)):
                leftovers.append(path)

    walk(catalog, "$")
    return leftovers


def main(argv=None):
    ap = argparse.ArgumentParser(description="ThaiVPN Connect 2.4 catalog/profile decoder")
    ap.add_argument("--catalog", action="store_true",
                    help="fetch the live catalog")
    ap.add_argument("--file", metavar="PROFILE.JSON",
                    help="decode an app profile.json file")
    ap.add_argument("--encrypt", metavar="CATALOG.JSON",
                    help="encrypt a decoded catalog JSON into profile.json format")
    ap.add_argument("--out", metavar="FILE", help="write result JSON/text here")
    ap.add_argument("--redacted", metavar="FILE",
                    help="also write the redacted catalog here (with --catalog/--file)")
    ap.add_argument("--check-catalog", action="store_true",
                    help="fetch live catalog and verify no encoded value remains")
    args = ap.parse_args(argv)

    if args.encrypt:
        with open(args.encrypt, "r", encoding="utf-8") as fh:
            catalog = json.load(fh)
        blob = encrypt_blob(catalog)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(blob)
        else:
            print(blob)
        return 0

    if args.catalog or args.check_catalog:
        catalog = fetch_catalog()
    elif args.file:
        catalog = decode_profile_file(args.file)
    else:
        ap.error("use --catalog, --file or --encrypt")
        return 2

    if args.check_catalog:
        leftovers = find_leftover_encoded(catalog)
        print(f"Version: {catalog.get('Version')}")
        print(f"Servers: {len(catalog.get('Servers', []))}")
        print(f"Networks: {len(catalog.get('Networks', []))}")
        if leftovers:
            print("LEFTOVER ENCODED VALUES:")
            for path in leftovers:
                print("  " + path)
            return 1
        print("OK: no encoded value remains")
        return 0

    text = json.dumps(catalog, indent=2, ensure_ascii=False)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        print(text)
    if args.redacted:
        with open(args.redacted, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(redact_catalog(catalog), indent=2,
                                ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
