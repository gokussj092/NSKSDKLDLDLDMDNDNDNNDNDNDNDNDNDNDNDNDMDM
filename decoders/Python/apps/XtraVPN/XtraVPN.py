#!/usr/bin/env python3
"""XtraVPN 1.0.36 (com.xtravpn.dev): catalog decoder, local or explicit HTTPS.

Standalone Python 3.10+, standard library only; no APK needed at runtime.
No XtraVPN_archivos.py: the app's only file format is .sks (imported
through ConfigImportFileActivity, manifest pathPattern .*\\.sks), and
.sks files are excluded from SP-DECODE work. The app accepts shared text
(ACTION_SEND EXTRA_TEXT) through ImportActivity, but that text is the
same encrypted config blob this script decodes, not a separate format.
There is no own URI scheme (no xtravpn://); the manifest only declares
file/content (for .sks), https (a <queries> entry, not a deep link),
sms and tel.

Method (verified against this APK, versionCode 62, versionName 1.0.36,
downloaded from APKPure; the public Google Play version is also 1.0.36):

Catalog (outer layer, LC7 / uW):
  The app has NO public vendor catalog URL. The server list is
  downloaded only from a per-device "custom code" URL:
    SharedPreferences "AppPreferences" -> "customCode"
    -> Vj0.h(code, android_id): AES-128-ECB, key = first 16 bytes of the
       Android ID, data = Base64 -> if the result starts with "https://"
       that is the URL (the fixed fallback constant "23605c1568999d3a"
       is 12 bytes after Base64 and cannot decrypt, so it is dead).
    -> Lv0.run(): plain GET via HttpURLConnection, no custom headers,
       connect/read timeouts 5000 ms, non-200 -> "Error on getting data:
       HTTP <code>".
    -> LAK callback: the downloaded string is decrypted with the
       MainActivity key B0 (the AdMob banner ID, see below) via LuW.i
       (XXTEA) and validated by comparing the "Version" field
       segment-by-segment against the current config; if newer it is
       saved (still encrypted) to filesDir/Config.json.
  The bundled asset assets/config/config.json is the same envelope
  (Base64 -> XXTEA) with the ServersActivity key "Pitingo2089".
  This script's --url therefore accepts the user-supplied custom-code
  URL (or any URL serving the same envelope) and tries BOTH keys,
  B0 first (the app's remote path) then "Pitingo2089", reporting
  which one opened it. Without a custom-code URL there is nothing
  live to fetch; the bundled asset is the verifiable catalog.

  Outer envelope (both keys, uW.s / uW.h, delta 0xF5D09E4D):
    Base64 -> XXTEA decrypt, key = UTF-8 bytes of the key string
    padded/truncated to 16 bytes, little-endian words, last word =
    plaintext length (must satisfy len-7 <= m <= len-4) -> JSON.
    Keys: "Pitingo2089" (ServersActivity, hj case 6) and
    "ca-app-pub-1778627428199734/4229593543" (XtravpnMainActivity,
    hj case 17, the AdMob banner unit ID).

Server fields (Sp0.l, after the outer JSON is open; every decrypted
value then passes through XA.b, a Caesar shift of -1 on letters,
because XtravpnMainActivity.a == 1, i.e. shift = 26 - 1 = 25):
    ServerIP   Vj0.h(data, r58): AES-128-ECB, key = first 16 bytes of
               r58, data = Base64 -> hostname (the asset holds
               "unpkg.com", not a numeric IP).
    ServerUser uW.i(data, r56): Base64 -> XXTEA (same delta, key =
               first 16 bytes of r56) -> username.
    Payload    K9.h(r55, data) -> Caesar -1 -> HTTP payload text
               (with [crlf] / [split] markers).
    SNI        K9.h(r55, data) -> Caesar -1 -> SNI hostname.
    udpserver  K9.h(r56, data) -> Caesar -1 (empty in the asset).
    udpobfs    K9.h(r57, data) -> Caesar -1 (empty in the asset).
    v2rayJson  K9.h(r58, data) -> Caesar -1 (empty in the asset).
    Slowchave / Nameserver / Slowdns / udpauth / udpbuffer / udpdown /
    udpup are read as plaintext (empty in the asset).
    ServerPass is NEVER read by the app (the literal does not occur
    in classes.dex); the SSH password is derived at runtime by
    Sp0.g (see derive_ssh_password). The asset's ServerPass is a
    placeholder that opens with K9.h(r57) to a test string with
    emojis, and is ignored.
    K9.h(key, data): pair-decode the data with the 16-char alphabet
    ":;<=>?!\\"#$%&'()*" (first char = high nibble, second = low
    nibble) -> Base64 text -> Base64 decode -> AES-256-CBC, key =
    SHA-256 of the UPPERCASE hex of the key's UTF-8 bytes, IV = 16
    zero bytes -> UTF-8. (The full 27-char alphabet string is
    Base64("Ojs8PT4/ISIjJCUmJygpKissLS4ve3x9fis9"); only its first
    16 chars occur in the data.)
    Field keys (20-char constants built in Lys.a, case 1):
      r55 = "D7FoVFa7UrpkAuc03rQc"  (Payload, SNI)
      r56 = "e6iQG0hiMfZWO8aOmLJY"  (ServerUser, udpserver)
      r57 = "cNEi7mEOyQyxRX5A275J"  (udpobfs, and the ServerPass
                                      placeholder)
      r58 = "eXjaA5SFxj5vr4t1sjql"  (ServerIP, v2rayJson)

SSH password (Sp0.g, time-varying, rotates every UTC hour):
    sshPass = SHA-256 hex (lowercase) of
      ServerUser(Caesar-shifted) + YYYYMMDDHH (UTC) +
      "MiClaveSecreta2024XYZ" (Sp0.j) + slice1 + noise1 + slice2 +
      "ZyxClave9087Secreta\\x00" (Sp0.k, 19 bytes incl. trailing NUL)
      + noise2 + slice3 + noise3, first 16 hex chars.
    slice1/2/3 are substrings of the lowercase hex of the SHA-256 of
    the APK signing certificate (QV.g), at the sig indices; noise1/2/3
    are the sig noise strings. Defaults (Ljt.b, used when the remote
    sig config cannot be fetched, which is the case today -- see
    below): indices (5,7,18,6,38,5), noise ("k9Xm2P","Tz7nWq",
    "Rb4vYj"). For this APK the certificate SHA-256 (from the v2
    signature block) is
    0724df38ff26b2d54bc9ffbe4de63a374b9080368af08f2b50fc02dd4cf58a62
    so the default slices are "f38ff26", "c9ffbe", "368af".
    A second Ld2.run path uses adjusted indices (start1+3, start2+5,
    start3+2) with noise ("x9Km3R","Pq8nVw","Tz2jYb"); pass
    --sig to reproduce it. The script defaults to the primary path.

Sig config (remote, currently undecryptable -- honest failure):
    Ljt.a fetches https://cdn.toolsp.site/05da6d93ed43e5ff/259bc7b35aa0
    (plain GET) and K9-decodes it with the fixed key
    "xF6qT4S41xonP9eAwQ" (20 bytes built in Ljt.a). The JSON would
    carry version / sig_start* / sig_length* / noise1-3, and when
    version > stored sig_version the app saves them to
    "sig_config_prefs". The content served today (473 bytes, stable
    across fetches and User-Agents, SHA-256
    2313681f2ff7753d4b7d5e0865edda7ef70fefd0f3f664b2814d94e56b0c8362)
    does NOT decrypt with that key (bad PKCS#7 padding with every
    key derivation tried), so the app itself would throw
    "config_error" and keep the defaults. --sig-config reports this
    instead of inventing values.

Admin messages (NOT a catalog):
    SMS_Updater downloads https://bitbin.it/UJoIPP7n/raw (plain GET)
    and parses it directly as JSON {SendMessage, MyMessage}. The
    content served today is a K9-style obfuscated blob (5520 bytes),
    not JSON, so the current app build cannot parse it either. It is
    an admin-message feed, not server data; the script does not treat
    it as a catalog.

Live status (2026-11-13, verified with this script):
    * Bundled asset: opens with "Pitingo2089": Version 1.0.0, 1
      server ("Tigo Panamá. Op-1", PA), 0 payloads section (the
      payload lives inside the server's Payload field).
    * No vendor catalog URL exists, so there is no live catalog to
      fetch without a per-device custom-code URL; --url with a
      supplied URL tries B0 then "Pitingo2089".
    * Sig config endpoint: HTTP 200 but content does not decrypt
      with the app's key (see above).
    * bitbin admin feed: HTTP 200 but content is not JSON.
    Pending: a real Config.json downloaded on a phone (custom-code
    config) or the decrypted custom-code URL, to confirm the remote
    path end-to-end; a real .sks is excluded by request.

"Pitingo2089", the AdMob ID, the four r55-r58 keys, the K9 key for
the sig config and the Sp0.j/Sp0.k constants are format constants
baked into the app, not account credentials. The decoded catalog
holds the provider's own public server list; server usernames and
the derived time-based SSH password are that list's own fields,
shown only in the decoded output.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime, timezone
from http.client import HTTPException
import json
import re
import struct
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
MASK = 0xFFFFFFFF

XXTEA_DELTA = 0xF5D09E4D
# Outer catalog keys (LC7 instances; see module docstring).
KEY_SERVERS = "Pitingo2089"
KEY_MAIN = "ca-app-pub-1778627428199734/4229593543"
# Server-field keys (Lys.a, case 1).
KEY_R55 = "D7FoVFa7UrpkAuc03rQc"
KEY_R56 = "e6iQG0hiMfZWO8aOmLJY"
KEY_R57 = "cNEi7mEOyQyxRX5A275J"
KEY_R58 = "eXjaA5SFxj5vr4t1sjql"
# Sig-config endpoint and its fixed K9 key (Ljt.a).
SIG_CONFIG_URL = "https://cdn.toolsp.site/05da6d93ed43e5ff/259bc7b35aa0"
SIG_CONFIG_KEY = "xF6qT4S41xonP9eAwQ"
# Admin-message feed (SMS_Updater; NOT a catalog).
ADMIN_FEED_URL = "https://bitbin.it/UJoIPP7n/raw"
# Signing certificate SHA-256 (lowercase hex) of this APK, from the
# APK Signature Scheme v2 block; QV.g hashes the certificate bytes.
CERT_SHA256_HEX = "0724df38ff26b2d54bc9ffbe4de63a374b9080368af08f2b50fc02dd4cf58a62"
# Default sig indices/noise (Ljt.b).
SIG_DEFAULT = {
    "start1": 5, "length1": 7,
    "start2": 18, "length2": 6,
    "start3": 38, "length3": 5,
    "noise1": "k9Xm2P", "noise2": "Tz7nWq", "noise3": "Rb4vYj",
}
# Second Ld2.run path: same base indices, adjusted.
SIG_ADJUSTED = {
    "start1": 8, "length1": 7,
    "start2": 23, "length2": 6,
    "start3": 40, "length3": 5,
    "noise1": "x9Km3R", "noise2": "Pq8nVw", "noise3": "Tz2jYb",
}
# Sp0.j / Sp0.k constants used by the SSH-password derivation.
SP0_J = b"MiClaveSecreta2024XYZ"
SP0_K = b"ZyxClave9087Secreta\x00"
# Caesar shift applied by XA.b: shift = 26 - XtravpnMainActivity.a,
# and a == 1, so the effective shift is -1 (25 forward).
CAESAR_SHIFT = 25
K9_ALPHABET = ':;<=>?!"#$%&\'()*+,-./{|}~+='
_K9_INDEX = {}
for _i, _c in enumerate(K9_ALPHABET):
    _K9_INDEX.setdefault(_c, _i)


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _text(data):
    if not isinstance(data, (bytes, str)):
        raise DecodeError("FORMAT_ERROR", "Se esperaba texto o bytes UTF-8.")
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    try:
        value = data.decode("utf-8-sig") if isinstance(data, bytes) else data.removeprefix("\ufeff")
    except UnicodeDecodeError as exc:
        raise DecodeError("NOT_UTF8", "La entrada no es texto UTF-8 válido.") from exc
    return value.strip()


def _base64(text: str) -> bytes:
    cleaned = re.sub(r"\s+", "", text)
    try:
        return base64.b64decode(cleaned, validate=False)
    except (binascii.Error, ValueError) as exc:
        raise DecodeError("BAD_BASE64", "El texto no es Base64 válido.") from exc


def _json(data: bytes):
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError("BAD_JSON", "El texto descifrado no es JSON válido.") from exc
    if not isinstance(doc, dict):
        raise DecodeError("BAD_JSON", "El JSON descifrado no es un objeto.")
    return doc


def _key16(key: str) -> bytes:
    raw = key.encode("utf-8")
    return raw[:16].ljust(16, b"\x00")


# ---------------------------------------------------------------- AES
# Pure-Python AES (decrypt only), same core as the AR PRO / Fat Tunnel
# decoders: S-box generated by the standard AES construction.
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



def _aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    if len(data) % 16:
        raise DecodeError("BAD_AES", "El cifrado AES-ECB no es múltiplo de 16.")
    out = bytearray()
    for i in range(0, len(data), 16):
        out += _aes_decrypt_block(key, data[i:i + 16])
    return bytes(out)


# ---------------------------------------------------------------- XXTEA
# uW.h / uW.s: modified XXTEA, delta 0xF5D09E4D (signed -170877363),
# little-endian words, last word = plaintext length.

def _xxtea_mx(z: int, y: int, total: int, p: int, e: int, k) -> int:
    return (
        (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
        ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z))
    ) & MASK


def _xxtea_decrypt(data: bytes, key16: bytes):
    if len(data) == 0:
        return b""
    if len(data) % 4:
        raise DecodeError("BAD_XXTEA", "El bloque XXTEA no es múltiplo de 4.")
    n = len(data) // 4
    v = list(struct.unpack("<%dI" % n, data))
    k = list(struct.unpack("<4I", key16))
    rounds = (52 // n) + 6
    total = (rounds * XXTEA_DELTA) & MASK
    y = v[0]
    while total != 0:
        e = (total >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - _xxtea_mx(z, y, total, p, e, k)) & MASK
            y = v[p]
        z = v[n - 1]
        v[0] = (v[0] - _xxtea_mx(z, y, total, 0, e, k)) & MASK
        y = v[0]
        total = (total - XXTEA_DELTA) & MASK
    plain_len = v[n - 1]
    out = struct.pack("<%dI" % n, *v)
    if plain_len < len(out) - 7 or plain_len > len(out) - 4:
        return None
    return out[:plain_len]


def _xxtea_encrypt(data: bytes, key16: bytes) -> bytes:
    # Used only by --self-test (round-trip). Packs the plaintext
    # little-endian (zero-padded) and appends the length word.
    n_words = (len(data) + 3) // 4
    v = list(struct.unpack("<%dI" % n_words, data.ljust(n_words * 4, b"\x00"))) if n_words else []
    v.append(len(data))
    n = len(v)
    k = list(struct.unpack("<4I", key16))
    rounds = (52 // n) + 6
    total = 0
    z = v[n - 1]
    for _ in range(rounds):
        total = (total + XXTEA_DELTA) & MASK
        e = (total >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            v[p] = (v[p] + _xxtea_mx(z, y, total, p, e, k)) & MASK
            z = v[p]
        y = v[0]
        v[n - 1] = (v[n - 1] + _xxtea_mx(z, y, total, n - 1, e, k)) & MASK
        z = v[n - 1]
    return struct.pack("<%dI" % n, *v)


# ---------------------------------------------------------------- K9 / Vj0 / Caesar
# K9.h(key, data): pair-decode -> Base64 -> AES-256-CBC (key =
# SHA-256 of the UPPERCASE hex of the key bytes, IV = 16 zero bytes).

def k9_decode(key: str, data: str) -> str:
    text = data.strip()
    if len(text) % 2:
        raise DecodeError("BAD_K9", "El texto K9 tiene longitud impar.")
    try:
        raw = bytes(
            ((_K9_INDEX[text[i]] * 16 + _K9_INDEX[text[i + 1]]) & 0xFF)
            for i in range(0, len(text), 2)
        )
    except KeyError as exc:
        raise DecodeError("BAD_K9", "El texto K9 tiene caracteres fuera del alfabeto.") from exc
    try:
        b64text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DecodeError("BAD_K9", "El texto K9 no decodifica a Base64.") from exc
    ciphertext = _base64(b64text)
    hexkey = key.encode("utf-8").hex().upper()
    import hashlib
    aeskey = hashlib.sha256(hexkey.encode("utf-8")).digest()
    try:
        plain = _aes_cbc_decrypt(aeskey, bytes(16), ciphertext)
        plain = _pkcs7_unpad(plain)
    except (ValueError, DecodeError) as exc:
        raise DecodeError("BAD_K9", "K9: padding AES inválido (clave incorrecta o datos corruptos).") from exc
    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecodeError("BAD_K9", "K9: el texto descifrado no es UTF-8.") from exc


def vj0_decode(data: str, key: str):
    """Vj0.h(data, key): AES-128-ECB, key = first 16 bytes of the key
    string (zero-padded), data = Base64. Returns None on failure
    (the app returns null and prints the stack trace)."""
    try:
        ciphertext = _base64(data.strip())
        plain = _aes_ecb_decrypt(_key16(key), ciphertext)
        try:
            plain = _pkcs7_unpad(plain)
        except ValueError:
            pass
        return plain.decode("utf-8")
    except (DecodeError, ValueError, UnicodeDecodeError):
        return None


def uw_decode(data: str, key: str):
    """uW.i(data, key): Base64 -> XXTEA (key = first 16 bytes).
    Returns None when the length word does not validate."""
    try:
        raw = _base64(data.strip())
    except DecodeError:
        return None
    try:
        plain = _xxtea_decrypt(raw, _key16(key))
    except DecodeError:
        return None
    if plain is None:
        return None
    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError:
        return None


def caesar_shift(text: str, shift: int = CAESAR_SHIFT) -> str:
    """XA.b: Caesar shift on letters only (shift forward mod 26).
    shift 25 == -1, the effective shift in this app."""
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + shift) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + shift) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


# ---------------------------------------------------------------- SSH password (Sp0.g)

def cert_slices(cert_hex: str, sig: dict):
    """QV.g slices of the lowercase cert SHA-256 hex."""
    h = cert_hex.lower()
    return (
        h[sig["start1"]:sig["start1"] + sig["length1"]],
        h[sig["start2"]:sig["start2"] + sig["length2"]],
        h[sig["start3"]:sig["start3"] + sig["length3"]],
    )


def derive_ssh_password(username: str, cert_hex: str = CERT_SHA256_HEX,
                        sig: dict = None, when: datetime = None) -> str:
    """Sp0.g: time-varying SSH password (16 lowercase hex chars).
    username must be the Caesar-shifted ServerUser. `when` is a UTC
    datetime (defaults to now); the value rotates every UTC hour."""
    import hashlib
    if sig is None:
        sig = SIG_DEFAULT
    s1, s2, s3 = cert_slices(cert_hex, sig)
    moment = when or datetime.now(timezone.utc)
    datestr = "%04d%02d%02d%02d" % (moment.year, moment.month, moment.day, moment.hour)
    combined = (
        username.encode("utf-8") + datestr.encode("utf-8") + SP0_J
        + s1.encode("utf-8") + sig["noise1"].encode("utf-8")
        + s2.encode("utf-8") + SP0_K
        + sig["noise2"].encode("utf-8")
        + s3.encode("utf-8") + sig["noise3"].encode("utf-8")
    )
    return hashlib.sha256(combined).hexdigest()[:16]


# ---------------------------------------------------------------- catalog

def decode_config(text, keys=(KEY_MAIN, KEY_SERVERS)):
    """Outer envelope: Base64 -> XXTEA -> JSON. Tries each key in
    order (B0 first: the app's remote path; then "Pitingo2089").
    Returns (config dict, key used). Raises DecodeError if no key
    opens it."""
    body = _text(text)
    raw = _base64(body)
    errors = []
    for key in keys:
        try:
            plain = _xxtea_decrypt(raw, _key16(key))
        except DecodeError as exc:
            errors.append("%s: %s" % (key, exc))
            continue
        if plain is None:
            errors.append("%s: la palabra de longitud XXTEA no valida" % key)
            continue
        try:
            return _json(plain), key
        except DecodeError as exc:
            errors.append("%s: %s" % (key, exc))
            continue
    raise DecodeError("NO_KEY", "Ninguna clave abre el catálogo. " + "; ".join(errors))


def decode_server(server: dict, cert_hex: str = CERT_SHA256_HEX,
                  sig: dict = None, when: datetime = None) -> dict:
    """Decodes one server entry (Sp0.l + XA.b). Fields the app never
    reads (ServerPass) are reported as stored, with the placeholder
    decode attempted for reference only."""
    if sig is None:
        sig = SIG_DEFAULT
    out = {"raw": server}
    # ServerIP: Vj0.h AES-ECB with r58, then Caesar.
    ip = server.get("ServerIP", "") or ""
    dec = vj0_decode(ip, KEY_R58) if ip.strip() else ""
    out["server_ip"] = caesar_shift(dec) if dec is not None else None
    # ServerUser: uW.i XXTEA with r56, then Caesar.
    user = server.get("ServerUser", "") or ""
    dec = uw_decode(user, KEY_R56) if user.strip() else ""
    out["server_user"] = caesar_shift(dec) if dec is not None else None
    # Payload / SNI: K9.h with r55, then Caesar.
    for field in ("Payload", "SNI"):
        value = server.get(field, "") or ""
        if value.strip():
            try:
                out[field.lower()] = caesar_shift(k9_decode(KEY_R55, value))
            except DecodeError:
                out[field.lower()] = None
        else:
            out[field.lower()] = ""
    # udpserver (r56), udpobfs (r57), v2rayJson (r58): K9.h + Caesar.
    for field, key in (("udpserver", KEY_R56), ("udpobfs", KEY_R57),
                       ("v2rayJson", KEY_R58)):
        value = server.get(field, "") or ""
        if value.strip():
            try:
                out[field.lower()] = caesar_shift(k9_decode(key, value))
            except DecodeError:
                out[field.lower()] = None
        else:
            out[field.lower()] = ""
    # Plaintext fields.
    for field in ("Slowchave", "Nameserver", "Slowdns", "udpauth",
                  "udpbuffer", "udpdown", "udpup", "ServerPort", "SSLPort",
                  "ProxyIP", "ProxyPort"):
        out[field.lower()] = server.get(field, "")
    # Flags.
    for field in ("isDirect", "isSSL", "isInject", "isSlow", "isudp",
                  "isV2ray", "isHysteria2", "isPayloadSSL", "isPayloadSSLrp",
                  "isBHTTP", "isV2rayInject", "isEcho"):
        out[field.lower()] = bool(server.get(field, False))
    # ServerPass: the app never reads it; report as stored. The
    # bundled asset's value is a placeholder that opens with r57.
    stored = server.get("ServerPass", "") or ""
    out["serverpass_stored"] = stored
    out["serverpass_placeholder"] = None
    if stored.strip():
        try:
            out["serverpass_placeholder"] = caesar_shift(k9_decode(KEY_R57, stored))
        except DecodeError:
            out["serverpass_placeholder"] = None
    # SSH password (derived, time-varying).
    if out.get("server_user"):
        out["ssh_user"] = out["server_user"]
        out["ssh_password"] = derive_ssh_password(out["server_user"], cert_hex, sig, when)
    else:
        out["ssh_user"] = None
        out["ssh_password"] = None
    return out


def decode(data, **kwargs):
    """Provider entry point: decode() returns the decoded catalog as
    a dict with the config plus every server fully decoded."""
    config, key = decode_config(data)
    servers = config.get("Servers", []) or []
    decoded = [decode_server(s, **kwargs) for s in servers]
    return {
        "version": config.get("Version"),
        "release_notes": config.get("ReleaseNotes"),
        "key_used": key,
        "server_count": len(decoded),
        "servers": decoded,
        "config": config,
    }


def version_is_newer(remote: str, current: str) -> bool:
    """LAK z(): compare the Version field segment by segment."""
    def parts(v):
        out = []
        for seg in str(v).split("."):
            try:
                out.append(int(seg))
            except ValueError:
                out.append(0)
        return out
    r, c = parts(remote), parts(current)
    for a, b in zip(r, c):
        if a != b:
            return a > b
    return len(r) > len(c)


def _fetch(url: str, timeout: int = 30) -> str:
    """Plain GET exactly as the app does it (HttpURLConnection, no
    custom headers). Returns the body as text."""
    req = Request(url, method="GET")
    opener = build_opener(HTTPRedirectHandler)
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read()
    except HTTPError as exc:
        raise DecodeError("HTTP_%d" % exc.code, "HTTP %d al descargar %s" % (exc.code, url)) from exc
    except (URLError, HTTPException, TimeoutError, OSError) as exc:
        raise DecodeError("NETWORK", "No se pudo descargar %s: %s" % (url, exc)) from exc
    if len(body) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La respuesta supera el límite de tamaño.")
    return body.decode("utf-8", "replace")


def run(url: str = None, data: str = None, path: str = None,
        sig: dict = None, when: datetime = None):
    """Fetch (plain GET) or read a local config blob and decode it.
    Returns the decoded catalog dict."""
    if data is None:
        if url:
            data = _fetch(url)
        elif path:
            data = Path(path).read_text(encoding="utf-8")
        else:
            raise DecodeError("NO_INPUT", "Falta --url, --file o datos.")
    return decode(data, sig=sig or SIG_DEFAULT, when=when)


def _self_test() -> int:
    checks = []

    def check(name, ok, detail=""):
        checks.append((name, ok, detail))
        print(("OK  " if ok else "FAIL") + " " + name + (" -- " + detail if detail else ""))

    # 1. Bundled asset (config.json next to this script).
    here = Path(__file__).resolve().parent
    asset = here / "config.json"
    if not asset.exists():
        check("asset config.json presente", False, "falta el archivo")
    else:
        raw = asset.read_text(encoding="utf-8")
        try:
            result = decode(raw)
            check("asset abre con Pitingo2089", result["key_used"] == KEY_SERVERS,
                  "Version %s, %d servidor(es)" % (result["version"], result["server_count"]))
            srv = result["servers"][0] if result["servers"] else {}
            check("ServerIP -> unpkg.com", srv.get("server_ip") == "unpkg.com", str(srv.get("server_ip")))
            check("ServerUser -> tipaop1", srv.get("server_user") == "tipaop1", str(srv.get("server_user")))
            payload = srv.get("payload", "")
            check("Payload es HTTP legible",
                  payload.startswith("GET / HTTP/1.9[crlf]host: unpkg.com"),
                  payload[:60].replace("\n", " "))
            check("SNI -> abc.greenp.site", srv.get("sni") == "abc.greenp.site", str(srv.get("sni")))
            check("ssh_password tiene 16 hex",
                  isinstance(srv.get("ssh_password"), str) and len(srv["ssh_password"]) == 16
                  and re.fullmatch(r"[0-9a-f]{16}", srv["ssh_password"]) is not None,
                  str(srv.get("ssh_password")))
        except DecodeError as exc:
            check("asset abre con Pitingo2089", False, "%s: %s" % (exc.code, exc))
    # 2. XXTEA round-trip (encrypt is only used by the self-test).
    sample = b'{"Version":"9.9.9","Servers":[]}'
    enc = _xxtea_encrypt(sample, _key16(KEY_SERVERS))
    dec = _xxtea_decrypt(enc, _key16(KEY_SERVERS))
    check("XXTEA round-trip", dec == sample)
    # 3. K9 round-trip is covered by the asset fields above; verify
    #    the sig-config failure is reported honestly, not hidden.
    try:
        body = _fetch(SIG_CONFIG_URL)
        try:
            k9_decode(SIG_CONFIG_KEY, body)
            check("sig-config descifra (inesperado)", False, "hoy no debería abrir")
        except DecodeError:
            check("sig-config NO descifra (fallo honesto)", True,
                  "HTTP 200, %d bytes, K9 con la clave de la app falla" % len(body))
    except DecodeError as exc:
        check("sig-config alcanzable", False, "%s: %s" % (exc.code, exc))
    failed = [c for c in checks if not c[1]]
    print("self-test: %d/%d OK" % (len(checks) - len(failed), len(checks)))
    return 1 if failed else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Decodificador del catálogo de XtraVPN 1.0.36 (com.xtravpn.dev).")
    parser.add_argument("--url", help="URL del config cifrado (la URL del custom code del dispositivo).")
    parser.add_argument("--file", help="Archivo local con el config cifrado (o config.json del asset).")
    parser.add_argument("--asset", action="store_true",
                        help="Decodifica el config.json incluido junto al script.")
    parser.add_argument("--sig-config", action="store_true",
                        help="Descarga la sig-config remota e intenta descifrarla con K9.")
    parser.add_argument("--sig", choices=["default", "adjusted"], default="default",
                        help="Juego de índices/noise de la firma (default: Ljt.b; adjusted: segundo camino de Ld2.run).")
    parser.add_argument("--ssh-pass", metavar="USUARIO",
                        help="Deriva la contraseña SSH (Sp0.g) para un usuario y la hora UTC actual.")
    parser.add_argument("--hour", metavar="AAAAMMDDHH",
                        help="Hora UTC para --ssh-pass (por defecto, la actual).")
    parser.add_argument("--self-test", action="store_true", help="Pruebas contra el asset incluido y los endpoints.")
    args = parser.parse_args(argv)

    sig = SIG_DEFAULT if args.sig == "default" else SIG_ADJUSTED

    if args.self_test:
        return _self_test()

    if args.sig_config:
        try:
            body = _fetch(SIG_CONFIG_URL)
        except DecodeError as exc:
            print("sig-config: ERROR %s: %s" % (exc.code, exc))
            return 1
        print("sig-config: HTTP 200, %d bytes" % len(body))
        try:
            plain = k9_decode(SIG_CONFIG_KEY, body)
            print("sig-config: descifró -> %s" % plain)
        except DecodeError as exc:
            print("sig-config: NO descifra con la clave de la app (%s: %s)" % (exc.code, exc))
            print("La app lanzaría config_error y seguiría con los valores por defecto.")
        return 0

    if args.ssh_pass:
        when = None
        if args.hour:
            try:
                when = datetime.strptime(args.hour, "%Y%m%d%H").replace(tzinfo=timezone.utc)
            except ValueError:
                print("--hour debe ser AAAAMMDDHH, p. ej. 2026111320")
                return 2
        print(derive_ssh_password(args.ssh_pass, CERT_SHA256_HEX, sig, when))
        return 0

    if args.asset:
        here = Path(__file__).resolve().parent
        args.file = str(here / "config.json")

    try:
        result = run(url=args.url, path=args.file, sig=sig)
    except DecodeError as exc:
        print("ERROR %s: %s" % (exc.code, exc))
        return 1

    print("XtraVPN 1.0.36 -- Version del catálogo: %s" % result["version"])
    print("Clave que abrió el config: %s" % result["key_used"])
    print("Servidores: %d" % result["server_count"])
    if result.get("release_notes"):
        print("ReleaseNotes: %s" % result["release_notes"])
    for i, srv in enumerate(result["servers"]):
        print("\n[%d] %s" % (i, srv["raw"].get("Name", "")))
        print("    ServerIP: %s  ServerUser: %s" % (srv.get("server_ip"), srv.get("server_user")))
        print("    sshPass (hora UTC actual): %s" % srv.get("ssh_password"))
        print("    SNI: %s" % srv.get("sni"))
        payload = srv.get("payload", "") or ""
        print("    Payload: %s" % (payload[:200] + ("..." if len(payload) > 200 else "")))
        for field in ("udpserver", "udpobfs", "v2rayjson", "slowchave",
                      "nameserver", "slowdns", "serverport", "sslport"):
            if srv.get(field):
                print("    %s: %s" % (field, srv[field]))
        flags = [f for f in ("isdirect", "isssl", "isinject", "isslow", "isudp",
                             "isv2ray", "ishysteria2") if srv.get(f)]
        print("    Flags: %s" % (", ".join(flags) if flags else "ninguno"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
