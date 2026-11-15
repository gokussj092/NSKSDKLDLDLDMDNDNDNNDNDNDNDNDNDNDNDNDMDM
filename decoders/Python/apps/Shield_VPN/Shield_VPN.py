#!/usr/bin/env python3
"""Shield VPN 18.0 (litron.shield.vpn): catalog decoder, local or explicit HTTPS.

Standalone Python 3.10+, standard library only; no APK needed at runtime.
See README.md here.

Method (verified against this APK, versionCode 18, versionName 18.0;
same format family as the SP-DECODE repo's Litron_VPN / com.fleet.vpn
codec, verified byte-for-byte against it with PyCryptodome):
  GET https://godtechprime.github.io/shieldneko.txt   (plain GET,
  no custom headers, no auth; the app fetches this NekoBox subscription
  URL - it appears three times in classes.dex - and GitHub Pages serves
  it for any User-Agent; verified byte-identical with a Dalvik UA and
  with plain urllib)
  -> response body is one line of invisible Unicode (U+2000..U+200F,
     each char is one nibble; two chars are one byte)
  -> nibble-unpack -> Base64 -> AES-256-CBC/PKCS7, key =
     SHA-256 of the UPPERCASE HEX of b"godtech25" (i.e. of the ASCII
     string "474F44544543483235"), IV = 16 zero bytes
     (CBC has no authentication; a wrong key fails the padding check)
  -> JSON with Version, ReleaseNotes, Servers[] and Networks[]
  -> every string value made only of carrier chars (U+2000..U+200F)
     is opened the same way (unpack -> Base64 -> AES-CBC, or raw
     unpack -> UTF-8 when it is not a ciphertext); in the live catalog
     this opens ServerUser, ServerPass, cfrUser and cfrPass of every
     server. Plaintext fields stay as-is.

Live test (2026-11-13, --url): HTTP 200, 360,456 bytes,
SHA-256 69eb22c155b86d39ff89067d504e82fcd1139f89b567a6adab5fa120abe338c7,
catalog Version 31.73, 8 servers, 65 networks (payloads).
Bundled asset (assets/config/config.json): Version 1, 5 servers,
15 networks; used by --self-test.

The app has no own importable config file format (no ACTION_VIEW file
filter and no own extension in the manifest or DEX), so there is no
Shield_VPN_archivos.py. Text links: the NekoBox MainActivity declares
the standard schemes sn://subscription, clash://install-config, sn://,
ss://, ssr://, socks://, socks4://, socksa://, sock5://, vmess://,
trojan://, trojan-go://, naive+https://, naive+quic:// and hysteria://;
no own scheme such as shield:// exists. Those standard protocols are
already covered by SP-DECODE.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
from http.client import HTTPException
from pathlib import Path
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_BYTES = 5 * 1024 * 1024
MAX_OUTPUT = 4 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
CATALOG_URL = "https://godtechprime.github.io/shieldneko.txt"
# Public app-wide format input (the same seed the Litron family uses);
# not an account credential.
SEED = b"godtech25"
KEY = hashlib.sha256(SEED.hex().upper().encode("ascii")).digest()
IV = bytes(16)
ALPHABET = "".join(chr(0x2000 + n) for n in range(16))


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- AES (pure python, stdlib only)
# Same verified core as AR_PRO_VPN.py (SP-DECODE batch 3).

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


_EXPANSION_CACHE = {}


def _key_expansion(key):
    cached = _EXPANSION_CACHE.get(key)
    if cached is not None:
        return cached
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
    result = (w, nr)
    _EXPANSION_CACHE[key] = result
    return result


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


# ---------------------------------------------------------------- helpers

def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _nonfinite(_value):
    raise ValueError("nonfinite number")


def _validate(doc):
    pending, count = [(doc, 0)], 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if depth > MAX_DEPTH or count > MAX_NODES:
            raise DecodeError("SIZE_LIMIT", "El JSON supera el límite de complejidad.")
        if isinstance(value, dict):
            pending.extend((v, depth + 1) for v in value.values())
            pending.extend((k, depth + 1) for k in value)
        elif isinstance(value, list):
            pending.extend((v, depth + 1) for v in value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise DecodeError("INVALID_JSON", "Número JSON no finito.")
        elif isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeError as exc:
                raise DecodeError("INVALID_JSON", "Unicode JSON inválido.") from exc
    return doc


def _json(data):
    try:
        doc = json.loads(data, object_pairs_hook=_unique, parse_constant=_nonfinite)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("INVALID_JSON", "JSON inválido o con claves duplicadas.") from exc
    if not isinstance(doc, dict):
        raise DecodeError("WRONG_DOCUMENT", "El documento debe contener un objeto JSON.")
    return _validate(doc)


def _render(doc):
    return (json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")


# ---------------------------------------------------------------- Litron carrier + CBC

def unpack(value):
    """Unicode nibble carrier -> bytes (two U+2000..U+200F chars = 1 byte)."""
    if not isinstance(value, str) or not value or len(value) % 2:
        raise DecodeError("INVALID_CARRIER", "Portador Unicode inválido.")
    if any(c not in ALPHABET for c in value):
        raise DecodeError("INVALID_CARRIER", "Carácter fuera del alfabeto del portador.")
    return bytes(
        (ord(value[i]) - 0x2000) * 16 + (ord(value[i + 1]) - 0x2000)
        for i in range(0, len(value), 2)
    )


def pack(raw):
    """Inverse of unpack (only for --self-test round-trip)."""
    return "".join(
        chr(0x2000 + (b >> 4)) + chr(0x2000 + (b & 0x0F)) for b in raw
    )


def cbc(raw):
    """AES-256-CBC/PKCS7 with the Litron key, IV = 16 zero bytes."""
    if not raw or len(raw) % 16:
        raise DecodeError("INVALID_BLOCK", "La longitud del cifrado no es múltiplo de 16.")
    try:
        plain = _pkcs7_unpad(_aes_cbc_decrypt(KEY, IV, raw))
    except ValueError as exc:
        raise DecodeError("DECRYPT_FAILED", "No se pudo descifrar (clave o formato incorrectos).") from exc
    try:
        return plain.decode("utf-8")
    except UnicodeError as exc:
        raise DecodeError("INVALID_UTF8", "El texto descifrado no es UTF-8 válido.") from exc


def open_outer(data):
    """Full catalog body -> parsed JSON document (hidden fields still encoded)."""
    if not isinstance(data, (bytes, str)) or not data:
        raise DecodeError("INVALID_INPUT", "La entrada está vacía.")
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    try:
        text = data.decode("utf-8") if isinstance(data, bytes) else data
    except UnicodeError as exc:
        raise DecodeError("INVALID_UTF8", "La entrada no es UTF-8 válido.") from exc
    # A .strip() here would corrupt this format: some carrier chars are
    # whitespace. Only a trailing newline is tolerated.
    text = text.removesuffix("\n").removesuffix("\r")
    raw = unpack(text)
    try:
        cipher = base64.b64decode(raw, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DecodeError("INVALID_BASE64", "El portador no contiene Base64 válido.") from exc
    if base64.b64encode(cipher) != raw:
        raise DecodeError("INVALID_BASE64", "Base64 no canónico.")
    return _json(cbc(cipher))


def hidden(value):
    """Open one string value that is entirely carrier chars, else keep it."""
    if not value or any(c not in ALPHABET for c in value):
        return value
    raw = unpack(value)
    candidates = []
    try:
        candidates.append(base64.b64decode(raw, validate=True))
    except (ValueError, binascii.Error):
        pass
    candidates.append(raw)
    for candidate in candidates:
        try:
            return cbc(candidate)
        except DecodeError:
            pass
    # Plain UTF-8 packed as nibbles (an empty string encrypts this way).
    return raw.decode("utf-8")


def walk(value):
    if isinstance(value, dict):
        return {k: walk(v) for k, v in value.items()}
    if isinstance(value, list):
        return [walk(v) for v in value]
    if isinstance(value, str):
        return hidden(value)
    return value


# ---------------------------------------------------------------- catalog

def decode(data):
    """Offline API: decrypt the complete catalog and return its dict."""
    doc = open_outer(data)
    if not isinstance(doc.get("Version"), str) or not doc["Version"]:
        raise DecodeError("WRONG_DOCUMENT", "El catálogo no trae Version.")
    for name in ("Servers", "Networks"):
        if not isinstance(doc.get(name), list):
            raise DecodeError("WRONG_DOCUMENT", "El catálogo no trae %s como lista." % name)
        if any(not isinstance(r, dict) or not isinstance(r.get("Name"), str) for r in doc[name]):
            raise DecodeError("WRONG_DOCUMENT", "Registros inválidos en %s." % name)
    result = walk(doc)
    out = _render(result)
    if len(out) > MAX_OUTPUT:
        raise DecodeError("SIZE_LIMIT", "La salida supera el límite de tamaño.")
    return _json(out.decode("utf-8"))


def run(file_bytes):
    """Offline API: complete catalog JSON or None; never a partial list."""
    try:
        return _render(decode(file_bytes)).decode("utf-8")
    except DecodeError:
        return None


# ---------------------------------------------------------------- download

def _https_url(url):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment):
        raise ValueError("invalid HTTPS URL")
    return parsed


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _plain_get(url, timeout=25):
    """One plain GET exactly as the app makes it: no custom headers, no auth."""
    request = Request(url, method="GET")
    with build_opener(_NoRedirect()).open(request, timeout=timeout) as response:
        if response.status != 200:
            raise DecodeError("DOWNLOAD_FAILED", "El endpoint no devolvió HTTP 200.")
        data = response.read(MAX_BYTES + 1)
    if not data or len(data) > MAX_BYTES:
        raise DecodeError("DOWNLOAD_FAILED", "La respuesta está vacía o supera el límite.")
    return data


def fetch_catalog(url=CATALOG_URL):
    """Download the catalog, retrying the plain GET; validates by decoding."""
    _https_url(url)
    last_error = None
    for _ in range(3):
        try:
            data = _plain_get(url)
            decode(data)
            return data
        except (DecodeError, OSError, HTTPError, URLError, HTTPException) as exc:
            last_error = exc
            time.sleep(1)
    raise DecodeError(
        "DOWNLOAD_FAILED",
        "No se pudo descargar un catálogo válido de Shield VPN.",
    ) from last_error


def _read(path):
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


def _self_test():
    """Decode the bundled asset (assets/config/config.json, Version 1)."""
    asset = Path(__file__).resolve().parent / "config.json"
    if not asset.is_file():
        raise DecodeError("SELF_TEST", "Falta config.json junto al script.")
    doc = decode(_read(asset))
    if doc.get("Version") != "1":
        raise DecodeError("SELF_TEST", "Version del asset inesperada: %r." % doc.get("Version"))
    if len(doc.get("Servers", [])) != 5 or len(doc.get("Networks", [])) != 15:
        raise DecodeError(
            "SELF_TEST",
            "Asset inesperado: %d servidores, %d redes."
            % (len(doc.get("Servers", [])), len(doc.get("Networks", []))),
        )
    if doc["Servers"][0].get("ServerUser") != "hone":
        raise DecodeError("SELF_TEST", "ServerUser del asset inesperado.")
    if doc["Servers"][0].get("ServerPass") != "0000":
        raise DecodeError("SELF_TEST", "ServerPass del asset inesperado.")
    # Carrier round-trip (pack/unpack are inverses).
    sample = b"Shield VPN self-test 1234"
    if unpack(pack(sample)) != sample:
        raise DecodeError("SELF_TEST", "Round-trip del portador falló.")
    return (
        "SELF-TEST OK: asset Version 1, 5 servidores, 15 redes; "
        "ServerUser/ServerPass abiertos; round-trip del portador OK."
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path, help="Respuesta del catálogo guardada localmente")
    source.add_argument("--url", nargs="?", const=CATALOG_URL, help="Descarga explícita; por defecto usa el endpoint original")
    source.add_argument("--self-test", action="store_true", help="Decodifica el asset incluido y verifica el método")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo; por defecto stdout")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            print(_self_test())
            return 0
        result = decode(fetch_catalog(args.url) if args.url is not None else _read(args.file))
        rendered = _render(result).decode("utf-8")
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        return 0
    except DecodeError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR", "message": "No se pudo leer o escribir el archivo."}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
