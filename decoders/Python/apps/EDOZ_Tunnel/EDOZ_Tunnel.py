#!/usr/bin/env python3
"""EDOZ Tunnel 3.7: catalog decoder only, local or explicit HTTPS.

Python 3.10+ standard library only (no PyCryptodome needed).

Method verified in net.androidtechvilla.edoztunnel 3.7 (versionCode 28):
  - Download: MainActivity.V0 -> l5.h (AsyncTask) -> Apache
    DefaultHttpClient, HttpGet on the URL as-is, no own headers, no
    params, no auth. Body read as ISO-8859-1 lines concatenated.
  - Decrypt: p5.f.a -> org.apache.commons.ssl.OpenSSL.decrypt("aes256",
    "securedjson", Base64.decode(body)), i.e. OpenSSL Salted__
    container, EVP_BytesToKey/MD5, AES-256-CBC/PKCS#7. On failure the
    app returns the input unchanged, so plain JSON starting with "{"
    is accepted as-is.
  - Version compare: MainActivity$b0.a parses the JSON and compares
    "Version" (as double) with the stored version; if newer it offers
    the update and saves the raw encrypted response in SQLite
    system.db / tcodes_table (ID 1 = free, ID 2 = VIP). m5.a.b()/g()
    read and decrypt those rows.
  - Bundled catalog: assets/defconf (and assets/vip_defconf, which
    is byte-identical to defconf in this build) is copied into that
    table on first run.

The free catalog URL serves the same bytes as EDOZ Tunnel Pro's free
catalog (same SHA-256, verified 2026-11-13). The VIP URL field
(p5.d.d) is empty by default in this build, so there is no live VIP
endpoint to test; the VIP asset decrypts with the same password.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
CATALOG_URL = "https://raw.githubusercontent.com/chrisrepair/Updates/main/Edoztunnnel%20lite%20V7%202024"
# The app fetches with Apache DefaultHttpClient (l5.h) and sets no headers
# of its own; this is the User-Agent that stack sends implicitly. The
# server returns the same body for any User-Agent (verified live).
USER_AGENT = "Apache-HttpClient/UNAVAILABLE (java 1.4)"
# Shared OpenSSL format passphrase from p5.f, not an account credential.
CATALOG_PASSPHRASE = b"securedjson"
LIST_FIELDS = ("Servers", "PremiumServers", "Tweaks", "PremiumTweaks")
# Synthetic self-test vector: {"Version":"99.9","Message":"self-test",
# "Servers":[{"Name":"T1"}],"Tweaks":[{"Name":"P1","Payload":"x"}]}
# encrypted with the same method (EVP_BytesToKey/MD5 + AES-256-CBC,
# salt 0102030405060708).
_SELF_TEST_VECTOR = (
    "U2FsdGVkX18BAgMEBQYHCFv7L9sm/mvOeI1/JJR/9HVhPPcjj6zmZnFl3BXl26ELZul4h4XDrmHtFuIeFuiecKVrsM9j1Y00FF7KEEKT2KMTdTLbuteKpDnuvB8bMlfRVO4tv89fOk5MC6a5tJlAsd9rVreABXbEKq62cIagC2v+c7JLWz0Zd9L1ErRg2n/Y"
)


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


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


def _aes_decrypt_block(key, block, schedule=None):
    w, nr = schedule if schedule is not None else _key_expansion(key)
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
    schedule = _key_expansion(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        dec = _aes_decrypt_block(key, blk, schedule)
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


# ---------------------------------------------------------------- catalog

def _text(data: bytes | str) -> str:
    if not isinstance(data, (bytes, str)):
        raise DecodeError("FORMAT_ERROR", "Se esperaba texto o bytes UTF-8.")
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    try:
        value = data.decode("utf-8-sig") if isinstance(data, bytes) else data.removeprefix("\ufeff")
        if len(value.encode("utf-8")) > MAX_BYTES:
            raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    except UnicodeError as exc:
        raise DecodeError("FORMAT_ERROR", "La entrada no es UTF-8 válido.") from exc
    return value.strip()


def _base64(text: str) -> bytes:
    compact = re.sub(r"[ \t\r\n]", "", text)
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact) or len(compact) % 4 == 1:
        raise DecodeError("FORMAT_ERROR", "Se esperaba Base64 estándar.")
    try:
        return base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DecodeError("FORMAT_ERROR", "Base64 inválido.") from exc


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
        # strict=False: the live catalog carries raw control characters
        # inside string values (org.json tolerates them, as does the app).
        doc = json.loads(data, object_pairs_hook=_unique, parse_constant=_nonfinite, strict=False)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("INVALID_JSON", "JSON inválido o con claves duplicadas.") from exc
    if not isinstance(doc, dict):
        raise DecodeError("WRONG_DOCUMENT", "El catálogo debe contener un objeto JSON.")
    return _validate(doc)


def _evp_bytes_to_key(password: bytes, salt: bytes) -> tuple[bytes, bytes]:
    """OpenSSL EVP_BytesToKey, MD5, 1 iteration: 32-byte key + 16-byte IV."""
    material, previous = b"", b""
    while len(material) < 48:
        previous = hashlib.md5(previous + password + salt).digest()
        material += previous
    return material[:32], material[32:48]


def decrypt_catalog_text(data: bytes | str) -> str:
    text = _text(data)
    if text.startswith("{"):
        return text  # p5.f.a returns plaintext unchanged if OpenSSL cannot decode it.
    raw = _base64(text)
    if not raw.startswith(b"Salted__"):
        raise DecodeError("FORMAT_ERROR", "Se esperaba el contenedor OpenSSL Salted__ del catálogo.")
    if len(raw) < 32 or (len(raw) - 16) % 16:
        raise DecodeError("TRUNCATED", "El catálogo contiene bloques AES incompletos.")
    salt = raw[8:16]
    key, iv = _evp_bytes_to_key(CATALOG_PASSPHRASE, salt)
    try:
        plain = _pkcs7_unpad(_aes_cbc_decrypt(key, iv, raw[16:]))
        return plain.decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("DECRYPT_FAILED", "No se pudo descifrar este catálogo.") from exc


def decode(data: bytes | str) -> dict:
    doc = _json(decrypt_catalog_text(data))
    if not any(field in doc for field in LIST_FIELDS):
        raise DecodeError("WRONG_DOCUMENT", "No hay listas de servidores o tweaks en el catálogo.")
    for field in LIST_FIELDS:
        if field in doc and (not isinstance(doc[field], list) or any(not isinstance(v, dict) for v in doc[field])):
            raise DecodeError("WRONG_DOCUMENT", "Las listas de catálogo deben contener objetos completos.")
    return doc


def summary(doc: dict) -> dict:
    """Counts only: version plus the length of each catalog list. No values."""
    out = {"Version": doc.get("Version")}
    for field in LIST_FIELDS:
        if field in doc:
            out[field] = len(doc[field])
    tweaks = doc.get("Tweaks")
    if isinstance(tweaks, list):
        out["Payloads"] = sum(1 for t in tweaks if isinstance(t, dict) and t.get("Payload"))
    return out


def run(file_bytes: bytes | str) -> str | None:
    """Offline API: complete catalog JSON or None; never a partial list."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


class _HTTPSRedirect(HTTPRedirectHandler):
    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlsplit(newurl)
        if parsed.scheme != "https" or parsed.username is not None or parsed.password is not None:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_catalog(url: str = CATALOG_URL) -> bytes:
    try:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ValueError("invalid HTTPS URL")
        req = Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
        with build_opener(_HTTPSRedirect()).open(req, timeout=30) as response:
            if response.status != 200:
                raise OSError("unexpected HTTP status")
            data = response.read(MAX_BYTES + 1)
    except HTTPError as exc:
        code = "ACCESS_DENIED" if exc.code in (401, 403) else "DOWNLOAD_FAILED"
        raise DecodeError(code, "El endpoint no devolvió un catálogo accesible.") from exc
    except (OSError, ValueError, URLError, HTTPException) as exc:
        raise DecodeError("DOWNLOAD_FAILED", "No se pudo descargar el catálogo mediante HTTPS.") from exc
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La respuesta supera el límite de tamaño.")
    return data


def _read(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


def _write_output(path: Path, rendered: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, rendered.encode("utf-8"))
    finally:
        os.close(fd)


def _self_test() -> dict:
    checks = {}
    # 1. FIPS-197 AES-256 known answer (decrypt direction).
    key = bytes(range(0x00, 0x20))
    cipher = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    plain = _aes_decrypt_block(key, cipher)
    checks["aes256_fips197"] = plain == bytes.fromhex("00112233445566778899aabbccddeeff")
    # 2. Synthetic Salted__ envelope with the app's password.
    doc = decode(_SELF_TEST_VECTOR)
    checks["synthetic_envelope"] = (
        doc.get("Version") == "99.9"
        and len(doc.get("Servers", [])) == 1
        and len(doc.get("Tweaks", [])) == 1
    )
    # 3. Plain JSON passes through unchanged (as p5.f.a does on failure).
    checks["plain_json_passthrough"] = decode('{"Version":"1.0","Servers":[]}').get("Version") == "1.0"
    checks["ok"] = all(checks.values())
    return checks


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=False)
    source.add_argument("file", nargs="?", type=Path, help="Respuesta del catálogo guardada localmente (o assets/defconf del APK)")
    source.add_argument("--url", nargs="?", const=CATALOG_URL, help="Descarga explícita; por defecto usa el endpoint original")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo con modo 0600; por defecto stdout")
    parser.add_argument("--summary", action="store_true", help="Imprimir solo versión y recuentos, sin valores")
    parser.add_argument("--self-test", action="store_true", help="Verifica AES-256 (FIPS-197) y un sobre Salted__ sintético")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            result = _self_test()
            print(json.dumps(result, ensure_ascii=False))
            return 0 if result["ok"] else 1
        if args.url is not None:
            result = decode(fetch_catalog(args.url))
        elif args.file is not None:
            result = decode(_read(args.file))
        else:
            parser.error("se requiere un archivo, --url o --self-test")
        rendered = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            _write_output(args.output, rendered)
        if args.summary:
            sys.stdout.write(json.dumps(summary(result), ensure_ascii=False, indent=2, allow_nan=False) + "\n")
        elif not args.output:
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
