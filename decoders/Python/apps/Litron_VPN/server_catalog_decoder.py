#!/usr/bin/env python3
"""Fleet VPN / LITRON VPN (com.fleet.vpn) 3.5.9, build 25: catalog decoder.

Standalone Python 3.10+, standard library only; no APK needed at runtime.
See README.md here. For the SP-DECODE provider format: decode() takes the
raw catalog bytes and returns the decoded catalog dict; run() renders it
as JSON text; the CLI downloads (--url), reads a file, or reads --stdin.

Method (verified byte-for-byte in this APK, versionCode 25, and live):
  GET https://godtechprime.github.io/latestv2ray.txt
  headers: User-Agent: okhttp/5.0.0-alpha.3, Accept-Encoding: identity
  (no redirects, no auth)
  -> body is UTF-8 text in a Unicode nibble carrier: every character is
     U+2000..U+200F and each pair encodes one byte (high nibble first).
     NEVER strip() the body: part of the alphabet is Unicode whitespace
     (U+2000..U+200A are spaces, U+200B is a zero-width space).
  -> unpack pairs -> bytes -> Base64 (canonical) -> AES-256-CBC,
     key = SHA-256 of the uppercase hex of b"godtech25",
     IV = 16 zero bytes, PKCS#7 -> JSON {Version, Servers, Networks, ...}
  -> every string value made only of carrier characters is a hidden
     field: unpack -> try Base64 -> AES-CBC; else raw bytes -> AES-CBC;
     else plain UTF-8 packed as nibbles.
  The same format is used by the APK-bundled asset assets/config/config.json
  (v12, 5 servers / 5 networks); pass it as a file argument to decode it.
  CBC is unauthenticated: decryption proves the format, not the origin.

Live test (2026-11-13): HTTP 200, 446,856 bytes -> Version 293,
8 servers, 86 networks (72 with a non-empty Payload). The catalog marks
no free/premium/VIP flag anywhere: every listed server is served to all
users. The repo's earlier capture (2026-11-09) was v289, 8 servers,
86 networks; the format is unchanged.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

CATALOG_URL = "https://godtechprime.github.io/latestv2ray.txt"
AGENT = "okhttp/5.0.0-alpha.3"
# Public app-wide format input (the app's q.d/q.l constant); not an
# account credential.
SEED = b"godtech25"
KEY = hashlib.sha256(SEED.hex().upper().encode("ascii")).digest()
IV = bytes(16)
ALPHABET = "".join(chr(0x2000 + n) for n in range(16))
MAX_INPUT = 5 * 1024 * 1024
MAX_OUTPUT = 4 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000


class DecodeError(ValueError):
    """Catalog input is invalid or incompatible with this format."""


# ---------------------------------------------------------------- AES (pure python, stdlib only)

_SBOX = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
)
_INV_SBOX = (
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d,
)
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)


def _xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff


def _mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _key_expansion(key):
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = [_SBOX[t[1]] ^ _RCON[i // nk - 1], _SBOX[t[2]],
                 _SBOX[t[3]], _SBOX[t[0]]]
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w, nr


def _add_rk(s, w, rnd):
    for c in range(4):
        for r in range(4):
            s[4 * c + r] ^= w[4 * rnd + c][r]


def _sub(s, inv=False):
    box = _INV_SBOX if inv else _SBOX
    for i in range(16):
        s[i] = box[s[i]]


def _shift(s, inv=False):
    for r in range(1, 4):
        row = [s[4 * c + r] for c in range(4)]
        sh = (4 - r) if inv else r
        row = row[sh:] + row[:sh]
        for c in range(4):
            s[4 * c + r] = row[c]


def _mix(s, inv=False):
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        if inv:
            s[4 * c + 0] = _mul(a[0], 14) ^ _mul(a[1], 11) ^ _mul(a[2], 13) ^ _mul(a[3], 9)
            s[4 * c + 1] = _mul(a[0], 9) ^ _mul(a[1], 14) ^ _mul(a[2], 11) ^ _mul(a[3], 13)
            s[4 * c + 2] = _mul(a[0], 13) ^ _mul(a[1], 9) ^ _mul(a[2], 14) ^ _mul(a[3], 11)
            s[4 * c + 3] = _mul(a[0], 11) ^ _mul(a[1], 13) ^ _mul(a[2], 9) ^ _mul(a[3], 14)
        else:
            s[4 * c + 0] = _mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3]
            s[4 * c + 1] = a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3]
            s[4 * c + 2] = a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3)
            s[4 * c + 3] = _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)


def _aes_decrypt_block(key, block):
    w, nr = _key_expansion(key)
    s = list(block)
    _add_rk(s, w, nr)
    for rnd in range(nr - 1, 0, -1):
        _sub(s, True)
        _shift(s, True)
        _add_rk(s, w, rnd)
        _mix(s, True)
    _sub(s, True)
    _shift(s, True)
    _add_rk(s, w, 0)
    return bytes(s)


def _aes_cbc_decrypt(key, iv, data):
    if len(data) % 16:
        raise ValueError("ciphertext length must be a multiple of 16")
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        dec = _aes_decrypt_block(key, blk)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = blk
    return bytes(out)


def _pkcs7_unpad(data):
    if not data:
        raise ValueError("empty data")
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad PKCS#7 padding")
    return data[:-pad]



# ---------------------------------------------------------------- Litron carrier / CBC

def unpack(value):
    """Decode a Unicode nibble carrier string to bytes (U+2000+n pairs)."""
    if not isinstance(value, str) or not value or len(value) % 2:
        raise DecodeError("Invalid Litron carrier: empty or odd length.")
    if any(c not in ALPHABET for c in value):
        raise DecodeError("Invalid Litron carrier: character outside U+2000..U+200F.")
    return bytes(
        (ord(value[i]) - 0x2000) * 16 + ord(value[i + 1]) - 0x2000
        for i in range(0, len(value), 2)
    )


def _cbc_text(raw):
    """AES-256-CBC (key above, IV 16 zeros, PKCS#7) -> UTF-8 text."""
    if not raw or len(raw) % 16:
        raise DecodeError("Invalid Litron block length.")
    try:
        return _pkcs7_unpad(_aes_cbc_decrypt(KEY, IV, raw)).decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("AES-CBC open failed.") from exc


def _parse_json(text):
    """Strict JSON: no NaN/Infinity, no duplicate keys, bounded size/depth."""

    def no_const(name):
        raise ValueError(f"non-finite JSON constant {name}")

    def no_dupes(pairs):
        obj = {}
        for key, val in pairs:
            if key in obj:
                raise ValueError(f"duplicate JSON key {key!r}")
            obj[key] = val
        return obj

    try:
        doc = json.loads(
            text, parse_constant=no_const, object_pairs_hook=no_dupes
        )
    except (ValueError, RecursionError) as exc:
        raise DecodeError("Invalid Litron JSON.") from exc
    nodes = 0
    stack = [(doc, 0)]
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise DecodeError("Litron JSON too large or too deep.")
        if isinstance(node, dict):
            stack.extend((v, depth + 1) for v in node.values())
        elif isinstance(node, list):
            stack.extend((v, depth + 1) for v in node)
    return doc


def open_outer(data):
    """Open the outer envelope: carrier -> Base64 -> AES-CBC -> JSON dict."""
    if not isinstance(data, (bytes, bytearray)) or not 0 < len(data) <= MAX_INPUT:
        raise DecodeError("Invalid Litron input size.")
    # Never strip(): carrier characters include Unicode whitespace.
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeError as exc:
        raise DecodeError("Input is not valid UTF-8.") from exc
    raw = unpack(text)
    try:
        cipher = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DecodeError("Outer payload is not valid Base64.") from exc
    if base64.b64encode(cipher) != raw:
        raise DecodeError("Noncanonical Litron packing.")
    doc = _parse_json(_cbc_text(cipher))
    if not isinstance(doc, dict):
        raise DecodeError("Litron catalog is not a JSON object.")
    return doc


def hidden(value):
    """Open one hidden field, or return the value unchanged if it is plain."""
    if not value or any(c not in ALPHABET for c in value):
        return value
    raw = unpack(value)
    candidates = []
    try:
        candidates.append(base64.b64decode(raw, validate=True))
    except (binascii.Error, ValueError):
        pass
    candidates.append(raw)
    for candidate in candidates:
        try:
            return _cbc_text(candidate)
        except DecodeError:
            pass
    # Plain UTF-8 packed as nibbles (owner helper behaviour).
    try:
        return raw.decode("utf-8")
    except UnicodeError as exc:
        raise DecodeError("Hidden field is not valid UTF-8.") from exc


def walk(value):
    if isinstance(value, dict):
        return {k: walk(v) for k, v in value.items()}
    if isinstance(value, list):
        return [walk(v) for v in value]
    if isinstance(value, str):
        return hidden(value)
    return value


def _validate(doc):
    if not isinstance(doc.get("Version"), str) or not doc["Version"]:
        raise DecodeError("Invalid Litron version.")
    for name in ("Servers", "Networks"):
        section = doc.get(name)
        if not isinstance(section, list):
            raise DecodeError(f"Invalid Litron section {name}.")
        for record in section:
            if not isinstance(record, dict) or not isinstance(
                record.get("Name"), str
            ):
                raise DecodeError(f"Invalid Litron record in {name}.")


def decode(data):
    """Decode raw catalog bytes (remote body or bundled config.json)."""
    doc = walk(open_outer(data))
    _validate(doc)
    out = render(doc)
    if len(out.encode("utf-8")) > MAX_OUTPUT:
        raise DecodeError("Litron output exceeds limit.")
    return _parse_json(out)


def render(doc):
    return json.dumps(doc, ensure_ascii=False, sort_keys=True, indent=1)


def run(data):
    """Decode raw catalog bytes and return the full catalog as JSON text."""
    return render(decode(data))


# ---------------------------------------------------------------- download

class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise DecodeError("Litron redirect denied.")


def fetch_catalog(url=CATALOG_URL):
    """Download the catalog exactly as the app does (GET, okhttp UA)."""
    try:
        req = Request(
            url,
            headers={"User-Agent": AGENT, "Accept-Encoding": "identity"},
            method="GET",
        )
        with build_opener(_NoRedirect()).open(req, timeout=25) as resp:
            if resp.status != 200:
                raise DecodeError(f"Litron catalog HTTP {resp.status}.")
            if resp.headers.get("Content-Encoding", "identity") != "identity":
                raise DecodeError("Unexpected Litron content encoding.")
            data = resp.read(MAX_INPUT + 1)
    except DecodeError:
        raise
    except (HTTPError, URLError, OSError, ValueError) as exc:
        raise DecodeError(f"No se pudo descargar el catálogo: {exc}.") from exc
    if not data or len(data) > MAX_INPUT or data.startswith(b"<"):
        raise DecodeError("Invalid Litron download.")
    return data


# ---------------------------------------------------------------- self-test

def _self_test():
    """Offline check against the APK-bundled asset assets/config/config.json."""
    here = Path(__file__).resolve().parent
    asset = here / "config.json"
    if not asset.is_file():
        print("self-test: bundled config.json missing.", file=sys.stderr)
        return 1
    doc = decode(asset.read_bytes())
    checks = [
        ("Version", doc.get("Version") == "12"),
        ("Servers", len(doc.get("Servers", [])) == 5),
        ("Networks", len(doc.get("Networks", [])) == 5),
        ("server[0] Name", doc["Servers"][0].get("Name") == "GERMANY"),
        ("server[0] ServerIP", doc["Servers"][0].get("ServerIP") == "litronn.tech"),
        ("network[0] Payload", doc["Networks"][0].get("Payload", "").startswith("GET /")),
    ]
    failed = [name for name, ok in checks if not ok]
    print(f"self-test: {len(checks) - len(failed)}/{len(checks)} checks passed "
          f"(bundled asset v{doc.get('Version')}, "
          f"{len(doc['Servers'])} servers, {len(doc['Networks'])} networks).")
    if failed:
        print("failed:", ", ".join(failed), file=sys.stderr)
        return 1
    return 0


# ---------------------------------------------------------------- CLI

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Fleet VPN / LITRON VPN (com.fleet.vpn) catalog decoder."
    )
    parser.add_argument("file", nargs="?", type=Path,
                        help="local catalog file (e.g. bundled config.json)")
    parser.add_argument("--url", action="store_true",
                        help="download the live catalog from the app URL")
    parser.add_argument("--stdin", action="store_true",
                        help="read the raw catalog from stdin")
    parser.add_argument("-o", "--output", type=Path,
                        help="write the decoded JSON to this file")
    parser.add_argument("--self-test", action="store_true",
                        help="offline check against the bundled config.json")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    sources = [bool(args.file), args.url, args.stdin]
    if sum(sources) != 1:
        parser.error("Give exactly one of: a file, --url, or --stdin.")
    try:
        if args.file:
            data = args.file.read_bytes()
        elif args.url:
            data = fetch_catalog()
        else:
            data = sys.stdin.buffer.read(MAX_INPUT + 1)
        text = run(data)
    except DecodeError as exc:
        print(f"Fleet VPN: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Fleet VPN: cannot read input: {exc}", file=sys.stderr)
        return 1
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
