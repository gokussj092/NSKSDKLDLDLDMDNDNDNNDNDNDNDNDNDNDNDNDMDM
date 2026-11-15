#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TCx Tunnel Plus (org.tcx.tunnel.plus) 1.0.15 / build 115 — catalog decoder
for SP-DECODE.

Catalog
-------
URL (DEAD — verified 2026-11-14)::
    https://raw.githubusercontent.com/maunadonis/aug16/refs/heads/main/aug16

The app fetches it with a plain Volley GET (no custom headers, no body;
Volley.newRequestQueue + StringRequest).  The response must be a single
Base64 line (checked with the regex
``^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`` and a
minimum length of 16), then it is decrypted with RenzUtils.decrypt and
the version is compared with the current catalog; if newer it is saved
into a ZIP file named ``classes5.dex`` in filesDir with the entry
``a.rlb`` (the raw encrypted catalog body) and the app restarts.

As of 2026-11-14 the catalog is DEAD: the raw URL answers HTTP 404
("404: Not Found", 14 bytes) and the GitHub API confirms that the repo
``maunadonis/aug16`` and the user ``maunadonis`` both return 404
(account/repo deleted or renamed).  There is NO bundled catalog asset
in the APK (assets are only v2ray_config.json, geoip/geosite.dat, flags
and custom_routing_*).  So there is no live catalog to report — this
script reports the failure honestly (``CATALOG_DEAD``) instead of
inventing servers.  The decrypt pipeline below is nevertheless fully
verified: it was validated byte-for-byte against the native
``renz_decrypt`` in libovpn3.so running under Unicorn (see README.md).

Cipher (RENZ / 7NET family, recovered from libovpn3.so — see README.md)
-----------------------------------------------------------------------
Body = Base64( XXTEA( AES-128-CBC( JSON ) ) )

* Seed = the APK signing certificate SHA-256 fingerprint, lowercase hex
  (``c1d7cc7d6f31cf485d9c293f568f606792a27d15ad8176b1dbe5539ece5c9fc8``,
  subject CN=Adonis G. Maun, O=AGM Inc, C=PH — the same developer as the
  dead GitHub repo owner ``maunadonis``).  The seed lives in the native
  global ``import`` (.bss 0x49ea78) and is set at runtime from the APK
  signature (``getSignKey`` in libovpn3.so): the catalog / .tcx files
  only open in the ORIGINAL signed app — an anti-tamper binding.
* AES key  = SHA-256(seed)[:16], AES IV = 16 zero bytes, PKCS#7 padding.
* XXTEA    = standard XXTEA, delta 0x9E3779B9, rounds = 6 + 52//n,
  key = the same 16-byte key (truncated at the first NUL byte, like the
  native code does), last word = plaintext length.
* Every string field inside the JSON (server names, hosts, ports,
  network names, payloads, SNI, top-level Username / Password) is
  itself encrypted the same way:
  Base64( XXTEA( AES-128-CBC( plaintext ) ) ) with the same key/IV.
* There is NO extra per-byte transform on this path: the flattened
  helper at 0x43b734 in libovpn3.so is a memcpy trampoline, not a
  byte transform (verified by the native round-trip in README.md).

File format: the app has its own ``.tcx`` export (text file starting
with ``tcxtunnelplus://`` + the same mode-0 cipher of a JSON profile)
— see TCx_Tunnel_archivos.py.  Text scheme: ``tcxtunnelplus://``
(paste import; no intent-filter for the scheme in the manifest).

Cloud: there is no share-by-code / device registration / account in
this app.  The only "cloud" is the public GitHub-hosted catalog above
(now dead).  The app is free with ads; no login.

Pure Python standard library only.
"""

import argparse
import base64
import hashlib
import json
import struct
import sys
import urllib.request
import urllib.error

CATALOG_URL = "https://raw.githubusercontent.com/maunadonis/aug16/refs/heads/main/aug16"
# Volley (Android) default User-Agent.
USER_AGENT = "Dalvik/2.1.0 (Linux; U; Android 14; Redmi 14C Build/UP1A.231005.007)"

# APK signing certificate SHA-256 fingerprint, lowercase hex
# (META-INF/BNDLTOOL.RSA of the 1.0.15 APK; CN=Adonis G. Maun).
SEED = b"c1d7cc7d6f31cf485d9c293f568f606792a27d15ad8176b1dbe5539ece5c9fc8"
AES_KEY = hashlib.sha256(SEED).digest()[:16]
AES_IV = b"\x00" * 16

XXTEA_DELTA = 0x9E3779B9
_M32 = 0xFFFFFFFF


# ---------------------------------------------------------------- AES-128
# S-box generated from the AES spec (inverse in GF(2^8) mod x^8+x^4+x^3+x+1
# followed by the affine transform), so no 256-entry table is typed by hand.

def _gf_mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = ((a << 1) ^ (0x1B if a & 0x80 else 0)) & 0xFF
        b >>= 1
    return r


def _gf_inv(a):
    if a == 0:
        return 0
    for x in range(1, 256):
        if _gf_mul(a, x) == 1:
            return x
    raise ValueError("no inverse")


def _make_sbox():
    sbox = []
    for i in range(256):
        inv = _gf_inv(i)
        s = inv
        for shift in (1, 2, 3, 4):
            s ^= ((inv << shift) | (inv >> (8 - shift))) & 0xFF
        s ^= 0x63
        sbox.append(s & 0xFF)
    return sbox


_SBOX = _make_sbox()
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _aes_key_expand(key):
    """AES-128 key expansion -> 44 32-bit round-key words."""
    w = list(struct.unpack(">4I", key))
    for i in range(4, 44):
        temp = w[i - 1]
        if i % 4 == 0:
            rot = ((temp << 8) | (temp >> 24)) & _M32
            sub = (_SBOX[(rot >> 24) & 0xFF] << 24) | (_SBOX[(rot >> 16) & 0xFF] << 16) \
                | (_SBOX[(rot >> 8) & 0xFF] << 8) | _SBOX[rot & 0xFF]
            temp = sub ^ (_RCON[i // 4 - 1] << 24)
        w.append((w[i - 4] ^ temp) & _M32)
    return w


def _aes_decrypt_block(rk, block):
    """Decrypt one 16-byte AES-128 block (state kept as 16 bytes,
    column-major like the AES spec)."""
    s = bytearray(block)
    for c in range(4):
        for r in range(4):
            s[4 * c + r] ^= (rk[40 + c] >> (24 - 8 * r)) & 0xFF
    for rnd in range(9, 0, -1):
        # InvShiftRows + InvSubBytes
        t = bytearray(16)
        for r in range(4):
            for c in range(4):
                t[4 * c + r] = _INV_SBOX[s[4 * ((c - r) % 4) + r]]
        s = t
        # AddRoundKey
        for c in range(4):
            for r in range(4):
                s[4 * c + r] ^= (rk[4 * rnd + c] >> (24 - 8 * r)) & 0xFF
        # InvMixColumns
        t = bytearray(16)
        for c in range(4):
            a0, a1, a2, a3 = s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]
            t[4 * c] = _gf_mul(a0, 14) ^ _gf_mul(a1, 11) ^ _gf_mul(a2, 13) ^ _gf_mul(a3, 9)
            t[4 * c + 1] = _gf_mul(a0, 9) ^ _gf_mul(a1, 14) ^ _gf_mul(a2, 11) ^ _gf_mul(a3, 13)
            t[4 * c + 2] = _gf_mul(a0, 13) ^ _gf_mul(a1, 9) ^ _gf_mul(a2, 14) ^ _gf_mul(a3, 11)
            t[4 * c + 3] = _gf_mul(a0, 11) ^ _gf_mul(a1, 13) ^ _gf_mul(a2, 9) ^ _gf_mul(a3, 14)
        s = t
    # final round: InvShiftRows + InvSubBytes + AddRoundKey
    t = bytearray(16)
    for r in range(4):
        for c in range(4):
            t[4 * c + r] = _INV_SBOX[s[4 * ((c - r) % 4) + r]]
    s = t
    for c in range(4):
        for r in range(4):
            s[4 * c + r] ^= (rk[c] >> (24 - 8 * r)) & 0xFF
    return bytes(s)


def _aes128_cbc_decrypt(data, key=AES_KEY, iv=AES_IV):
    """AES-128-CBC decrypt with PKCS#7 unpadding. Returns b"" on bad input."""
    if not data or len(data) % 16 != 0:
        return b""
    rk = _aes_key_expand(key)
    out = bytearray()
    prev = iv
    for off in range(0, len(data), 16):
        block = data[off:off + 16]
        dec = _aes_decrypt_block(rk, block)
        out.extend(bytes(a ^ b for a, b in zip(dec, prev)))
        prev = block
    if not out:
        return b""
    pad = out[-1]
    if pad < 1 or pad > 16 or out[-pad:] != bytes([pad]) * pad:
        return b""
    return bytes(out[:-pad])


# ------------------------------------------------------------------ XXTEA

def _prepare_xxtea_key(key16):
    """Native code truncates the key at the first NUL byte."""
    k = bytearray(key16[:16].ljust(16, b"\x00"))
    for i in range(15):
        if k[i] == 0:
            for j in range(i + 1, 16):
                k[j] = 0
            break
    return list(struct.unpack("<4I", bytes(k)))


def _xxtea_decrypt(data, key16=AES_KEY):
    """Native xxtea_decrypt: delta 0x9E3779B9, rounds = 6 + 52//n,
    last word = plaintext length. Returns (plaintext, length)."""
    n = (len(data) + 3) // 4
    if n < 2 or not data:
        return b"", 0
    buf = bytearray(n * 4)
    buf[:len(data)] = data
    v = list(struct.unpack("<%dI" % n, buf))
    k = _prepare_xxtea_key(key16)
    rounds = 6 + 52 // n
    total = (rounds * XXTEA_DELTA) & _M32
    while total:
        e = (total >> 2) & 3
        y = v[0]
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            mx = ((((z >> 5) ^ ((y << 2) & _M32)) + ((y >> 3) ^ ((z << 4) & _M32)))
                  ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z))) & _M32
            v[p] = (v[p] - mx) & _M32
            y = v[p]
        z = v[n - 1]
        mx = ((((z >> 5) ^ ((y << 2) & _M32)) + ((y >> 3) ^ ((z << 4) & _M32)))
              ^ ((total ^ y) + (k[e] ^ z))) & _M32
        v[0] = (v[0] - mx) & _M32
        total = (total - XXTEA_DELTA) & _M32
    total_bytes = n * 4
    last = v[-1]
    if total_bytes - 7 <= last <= total_bytes - 4:
        return struct.pack("<%dI" % n, *v)[:last], last
    return b"", 0


# ------------------------------------------------------- field / catalog

def _b64_clean(text):
    if isinstance(text, bytes):
        text = text.decode("utf-8", "ignore")
    text = "".join(text.split())
    text += "=" * (-len(text) % 4)
    return text


def decrypt_field(value):
    """Decrypt one Base64 string field of the catalog (XXTEA then AES).
    Returns the plaintext string, or the original value if it is not an
    encrypted field."""
    if not value or not isinstance(value, str):
        return value
    try:
        raw = base64.b64decode(_b64_clean(value), validate=False)
    except Exception:
        return value
    if len(raw) < 4:
        return value
    xxtea_plain, _ = _xxtea_decrypt(raw)
    if not xxtea_plain:
        return value
    plain = _aes128_cbc_decrypt(xxtea_plain)
    if not plain:
        return value
    return plain.decode("utf-8", "replace")


def _decrypt_server(server):
    out = {}
    for key, val in server.items():
        out[key] = decrypt_field(val) if isinstance(val, str) else val
    return out


def _decrypt_network(network):
    out = {}
    for key, val in network.items():
        if key == "V2Ray" and isinstance(val, dict):
            out[key] = {k: (decrypt_field(v) if isinstance(v, str) else v)
                        for k, v in val.items()}
        else:
            out[key] = decrypt_field(val) if isinstance(val, str) else val
    return out


def decode(data):
    """Decode a raw catalog body (Base64 text/bytes) into a dict with all
    string fields decrypted.  Also accepts an already-decrypted catalog
    JSON. Raises ValueError on undecryptable input."""
    if isinstance(data, bytes):
        text = data.decode("utf-8", "ignore")
    else:
        text = data
    stripped = text.strip()
    if stripped.startswith("{"):
        # Already-decrypted catalog JSON.
        catalog = json.loads(stripped)
    else:
        try:
            raw = base64.b64decode(_b64_clean(text), validate=False)
        except Exception as exc:
            raise ValueError("catalog body is not Base64: %s" % exc)
        xxtea_plain, _ = _xxtea_decrypt(raw)
        if not xxtea_plain:
            raise ValueError("XXTEA layer failed (bad key or bad body)")
        plain = _aes128_cbc_decrypt(xxtea_plain)
        if not plain:
            raise ValueError("AES layer failed (bad key/padding or bad body)")
        try:
            catalog = json.loads(plain.decode("utf-8"))
        except Exception as exc:
            raise ValueError("decrypted body is not JSON: %s" % exc)
    catalog["Servers"] = [_decrypt_server(s) for s in catalog.get("Servers", [])]
    catalog["Networks"] = [_decrypt_network(n) for n in catalog.get("Networks", [])]
    catalog["SSLNetworks"] = [_decrypt_network(n)
                              for n in catalog.get("SSLNetworks", [])]
    catalog["Username"] = decrypt_field(catalog.get("Username", ""))
    catalog["Password"] = decrypt_field(catalog.get("Password", ""))
    return catalog


def fetch(url=CATALOG_URL, timeout=30):
    """Fetch the catalog exactly like the app does: plain GET, no custom
    headers, Volley/Dalvik User-Agent. Raises urllib.error.HTTPError on
    HTTP failures (the live catalog answers 404)."""
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def run(url=CATALOG_URL):
    """Fetch + decode the live catalog. Returns the catalog dict."""
    return decode(fetch(url))


# ------------------------------------------------------------- self-test
# Small known-answer vector: the JSON below, encrypted with the same
# pipeline (AES-128-CBC inside, XXTEA outside) and the same key/IV.
# The vector was verified against the native renz_decrypt in
# libovpn3.so under Unicorn (see README.md): the native code opens
# this exact body and returns the same JSON.
_SELFTEST_JSON = b'{"Version":"1","Servers":[],"Networks":[],"SSLNetworks":[],"Username":"","Password":"","Notes":"self-test"}'
_SELFTEST_B64 = (
    "x060a5rqeEtRsjdFFUH8Q7eLeBb2O8sufYclOCelsMrtX+XRXmHP+TjB3KBW/lt+1bDv7ko0kofz"
    "6kXAIYbfm/mF7DPMoD0/jVAi6to2u3DYdMHnPVY2ky+929NTihnJRmqQgqte18cgkGS6CROki+HK"
    "bos="
)


def _self_test():
    # 1) AES-128 known-answer test (FIPS-197, key 000102...0f).
    rk = _aes_key_expand(bytes(range(16)))
    ct = _aes_decrypt_block(rk, bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"))
    assert ct == bytes.fromhex("00112233445566778899aabbccddeeff"), \
        "AES-128 decrypt KAT failed: %s" % ct.hex()
    # 2) Full pipeline on the embedded known-answer vector.
    cat = decode(_SELFTEST_B64)
    assert cat["Version"] == "1", cat
    assert cat["Notes"] == "self-test", cat
    assert cat["Servers"] == [] and cat["Networks"] == [], cat
    print("self-test OK: AES-128 KAT + full pipeline (XXTEA + AES-128-CBC)")
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="TCx Tunnel Plus (org.tcx.tunnel.plus) catalog decoder")
    ap.add_argument("--url", default=CATALOG_URL,
                    help="catalog URL (default: live TCx URL, currently dead)")
    ap.add_argument("--file", help="decode a saved catalog body instead of fetching")
    ap.add_argument("--self-test", action="store_true",
                    help="run the built-in known-answer tests")
    ap.add_argument("--out", help="write the decoded JSON to this file")
    ap.add_argument("--json", action="store_true",
                    help="print the decoded catalog as JSON")
    args = ap.parse_args(argv)

    if args.self_test:
        _self_test()
        return 0

    if args.file:
        with open(args.file, "rb") as fh:
            catalog = decode(fh.read())
    else:
        try:
            catalog = run(args.url)
        except urllib.error.HTTPError as exc:
            print("CATALOG_DEAD: the catalog URL answers HTTP %d (%s)"
                  % (exc.code, exc.reason))
            print("URL: %s" % args.url)
            print("The GitHub repo/user that hosted the catalog is gone; "
                  "there is no live catalog to decode.")
            print("Use --file with a saved catalog body, or --self-test "
                  "to verify the decrypt pipeline.")
            return 2
        except urllib.error.URLError as exc:
            print("CATALOG_UNREACHABLE: %s" % exc.reason)
            return 2

    servers = catalog.get("Servers", [])
    networks = catalog.get("Networks", [])
    payloads = sum(1 for n in networks if n.get("Payload"))
    print("TCx Tunnel Plus — catalog v%s" % catalog.get("Version"))
    print("Servidores: %d" % len(servers))
    print("Networks (configs): %d" % len(networks))
    print("Networks con Payload: %d" % payloads)
    print("SSLNetworks: %d" % len(catalog.get("SSLNetworks", [])))
    print("Notes: %s" % catalog.get("Notes"))
    for s in servers:
        print("  - %s | %s | proto %s | TCP %s SSL %s | %s"
              % (s.get("Name"), s.get("ServerIPHost"), s.get("Protocol"),
                 s.get("OpenVPNTCPPort"), s.get("OpenVPNSSLPort"),
                 s.get("Subname", "").strip()))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(catalog, fh, indent=1, ensure_ascii=False)
        print("Guardado en %s" % args.out)
    if args.json:
        print(json.dumps(catalog, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
