#!/usr/bin/env python3
"""Peru VPN 4.1.0 (com.peru.vpn): catalog decoder, local or explicit HTTPS.

Standalone Python 3.10+, standard library only; no APK needed at runtime.
For the app's own config files (Zs.png / noobdev body) use
Peru_VPN_archivos.py. See README.md here.

Method (verified against this APK, versionCode 410, versionName 4.1.0,
a TunnelDoom/SocketClay build):
  GET https://web.tunneldoom.space/config.json   (plain GET, no auth;
  exactly what ConfigUpdateco does with HttpURLConnection; the
  endpoint answers HTTP 403 to a generic Python-urllib User-Agent, so
  the script sends the app's Dalvik User-Agent)
  -> response body is one Base64 line (631,000 bytes on 2026-11-13)
  -> Base64 decode -> XOR with SHA-256(b"test_key") cycled (the app's
     StringCrypter, key "test_key") -> drop the first 32 chars (the
     16-byte salt, hex) -> JSON with Version, ReleaseNotes, Servers[]
  -> each server's Base64 fields are decrypted with the app's NoobCrypt
     (AES/CBC/PKCS7Padding, key = SHA-256 of the NoobPass key string,
     IV = 16 zero bytes); plaintext fields stay as-is.
The live catalog has no "Payloads" array (ConfigUtil.getNetworksArray
reads one, but the server does not send it); each server carries its
own Payload field. There is no premium/free category in the schema:
every listed server is free.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from http.client import HTTPException
import hashlib
import json
import math
from pathlib import Path
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
CATALOG_URL = "https://web.tunneldoom.space/config.json"

# NoobPass.getKey() (com.tunneldoom.sshservice.util.crypt.NoobPass):
# star() bytes, XORed with cycling "QXWR", then reversed. A format
# constant, not a password.
_NOOB_STAR = bytes([
    117, 112, 49, 33, 5, 32, 44, 47, 15, 113, 38, 41,
    107, 54, 116, 115, 123, 49, 51, 48, 53, 42, 43, 36,
])
_NOOB_KEY_STRING = bytes(
    b ^ b"QXWR"[i % 4] for i, b in enumerate(_NOOB_STAR)
)[::-1].decode("utf-8")
_NOOB_KEY = hashlib.sha256(_NOOB_KEY_STRING.encode("utf-8")).digest()
_NOOB_IV = bytes(16)

# StringCrypter key: SHA-256 of the literal "test_key".
_CRYPT_KEY = hashlib.sha256(b"test_key").digest()

# Server fields that are NoobCrypt Base64 ciphertexts (the rest are plain).
ENCRYPTED_FIELDS = (
    "ServerIP", "ProxyIP", "ServerUser", "ServerPass", "Payload", "SNI",
    "Slowchave", "Nameserver", "Slowdns", "UdpBuffer", "UdpDown", "UdpUp",
    "V2rayConfig",
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


# The NoobCrypt key never changes, so its expansion is computed once.
_NOOB_EXPANDED = _key_expansion(_NOOB_KEY)


def _aes_decrypt_block(block):
    w, nr = _NOOB_EXPANDED
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


def _aes_cbc_decrypt(data):
    if len(data) % 16:
        raise ValueError("ciphertext length must be a multiple of 16")
    out = bytearray()
    prev = _NOOB_IV
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        dec = _aes_decrypt_block(blk)
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


def noob_decrypt(value):
    """App NoobCrypt.decrypt: AES/CBC/PKCS7, key = SHA-256(NoobPass key).

    Returns the plaintext string, or None when the value is not a
    NoobCrypt ciphertext (wrong length, bad padding, or not UTF-8).
    """
    if not isinstance(value, str):
        return None
    try:
        # The app's Base64 values may wrap mid-string (Android's
        # Base64.decode ignores whitespace); strip it all first.
        raw = base64.b64decode(re.sub(r"\s+", "", value), validate=True)
    except (ValueError, binascii.Error):
        return None
    if not raw or len(raw) % 16:
        return None
    try:
        plain = _pkcs7_unpad(_aes_cbc_decrypt(raw))
        return plain.decode("utf-8")
    except (ValueError, UnicodeError):
        return None


# ---------------------------------------------------------------- helpers

def _text(data):
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


def _base64(text):
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
        doc = json.loads(data, object_pairs_hook=_unique, parse_constant=_nonfinite)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("INVALID_JSON", "JSON inválido o con claves duplicadas.") from exc
    if not isinstance(doc, dict):
        raise DecodeError("WRONG_DOCUMENT", "El documento debe contener un objeto JSON.")
    return _validate(doc)


# ---------------------------------------------------------------- StringCrypter (outer layer)

def stringcrypter_decrypt(data):
    """App StringCrypter.processString('d', body).

    Base64 -> XOR with SHA-256(b"test_key") cycled -> drop the first 32
    chars (the 16-byte salt, hex) -> catalog JSON text.
    """
    raw = _base64(_text(data))
    plain = bytes(b ^ _CRYPT_KEY[i % len(_CRYPT_KEY)] for i, b in enumerate(raw))
    try:
        text = plain.decode("utf-8")
    except UnicodeError as exc:
        raise DecodeError("DECRYPT_FAILED", "El cuerpo no descifra con StringCrypter.") from exc
    if len(text) < 33 or not re.fullmatch(r"[0-9a-f]{32}", text[:32]):
        raise DecodeError("DECRYPT_FAILED", "El cuerpo no trae la sal de 32 hex del formato.")
    return text[32:]


# ---------------------------------------------------------------- catalog

def _decrypt_server(server):
    """NoobCrypt-decrypt the server's Base64 fields; the rest stay as-is."""
    if not isinstance(server, dict):
        return server
    out = dict(server)
    for field in ENCRYPTED_FIELDS:
        value = out.get(field)
        if isinstance(value, str) and value.strip():
            decrypted = noob_decrypt(value)
            if decrypted is not None:
                out[field] = decrypted
    return out


def decrypt_catalog_bytes(data):
    """Base64 response body -> StringCrypter -> catalog JSON bytes."""
    return stringcrypter_decrypt(data).encode("utf-8")


def decode(data):
    """Offline API: decrypt the complete catalog and return its dict."""
    doc = _json(decrypt_catalog_bytes(data))
    if "Servers" not in doc or "Version" not in doc:
        raise DecodeError("WRONG_DOCUMENT", "El catálogo no trae Version ni Servers.")
    if not isinstance(doc["Servers"], list):
        raise DecodeError("WRONG_DOCUMENT", "Servers debe ser una lista.")
    doc["Servers"] = [_decrypt_server(server) for server in doc["Servers"]]
    return doc


def run(file_bytes):
    """Offline API: complete catalog JSON or None; never a partial list."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
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
    """One plain GET exactly as the app makes it: no auth, no params.

    The app's HttpURLConnection sends the Dalvik User-Agent; the
    endpoint answers HTTP 403 to a generic Python-urllib User-Agent,
    so the Dalvik UA is part of the exact request. The endpoint
    answers 200 with Content-Length, so the body is read whole;
    completeness is validated by the StringCrypter/JSON decode
    afterwards.
    """
    request = Request(url, method="GET", headers={
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 14)",
    })
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
        "No se pudo descargar un catálogo válido de Peru VPN.",
    ) from last_error


def _read(path):
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path, help="Respuesta del catálogo guardada localmente")
    source.add_argument("--url", nargs="?", const=CATALOG_URL, help="Descarga explícita; por defecto usa el endpoint original")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo; por defecto stdout")
    args = parser.parse_args(argv)
    try:
        result = decode(fetch_catalog(args.url) if args.url is not None else _read(args.file))
        rendered = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
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
