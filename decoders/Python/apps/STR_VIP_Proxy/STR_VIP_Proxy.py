#!/usr/bin/env python3
"""STR VIP Proxy (app.isvsoft.strvipproxy, versionCode 1, versionName 1.42.5):
catalog decoder, local or explicit HTTPS.

Standalone Python 3.10+, standard library only; no APK needed at runtime.
For .isc files, .ovpn/.conf, isv-config:// links, ISV- cloud codes and
VMess/VLESS/Trojan/Shadowsocks/WireGuard links use STR_VIP_Proxy_archivos.py.

Method verified against this APK (base.apk + split_config.arm64_v8a.apk):
  * Download: OkHttp interceptors LA6/a and Le7/a (classes3.dex) build the
    request. GET the worker URL below with User-Agent
    "ISVSOFT-CloudSync/2.0" plus, for paths containing "api/app" or "/app",
    the App-Proof headers X-ISV-Timestamp (unix seconds), X-ISV-Nonce
    (UUID without dashes) and X-ISV-Signature, from ISVCrypto.c(path) ->
    nativeSignProof. The server rejects other User-Agents (403
    "Forbidden: Unauthorized Client User-Agent.") and requests without the
    proof headers (403 "Forbidden: Missing Native App-Proof credentials.").
  * Signature: HMAC-SHA256(key, "timestamp:nonce:path") hex-encoded, where
    path is the request's encoded path WITHOUT the query string (e.g.
    "/api/app" — the OkHttp interceptor passes encodedPath to
    nativeSignProof; a signature over path+query fails server-side
    validation with 403 "Forbidden: Missing Native App-Proof credentials.").
    Verified against nativeSignProof (libisvcrypto.so, Unicorn emulation)
    on four test vectors, and against the live server for both endpoints.
  * Response: plain JSON (gzip transport encoding), NOT encrypted at the
    transport level. Every sensitive value inside the JSON is an "enc:"
    token (servers' hosts, settings credentials, cert profiles, tweak
    fields). ISVCrypto.a() decrypts them, looping up to 5 times while the
    result still starts with "enc:" (nested encryption).
  * enc: token = "enc:" + base64url( nonce(12 random) || AES-256-GCM(key,
    plaintext) ), where the GCM output is ciphertext || tag(16). The key
    is the SAME 32-byte ASCII constant as the HMAC key. Raw token length
    is always plaintext length + 28 bytes. Verified byte-for-byte against
    the native library (Unicorn emulation: decrypt of a known token and
    decrypt of native encrypt outputs) and against the `cryptography`
    package on all 1,951 enc: values in the live + bundled catalogs
    (1,888 live, 40 bundled, 0 failures). The AES-256-GCM below is a
    pure-Python implementation (stdlib only) validated by that same
    cross-check; it is not a guess.
  * The bundled assets (assets/servers.json, assets/settings.json,
    assets/tweaks.json) are the same format at catalog version 1.0.0
    (9 servers, 11 tweaks); the live catalog is version 1.0.31.

The server truncates the ~487 KB "full" response over plain HTTP/1.1
through some proxies (random cuts; the server ignores Range and always
answers 200 with the full body). This script first tries the plain GET
the app makes (3 attempts, validating Content-Length and gzip
integrity) and, only if it does not complete, retries the identical
request with `curl --http2` when curl is available. That fallback is a
transport workaround, not part of the app's request. The lighter
"type=servers" endpoint (~11 KB) downloads fine over plain HTTPS.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import time
import uuid
from http.client import HTTPException, IncompleteRead
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000

# 32-byte ASCII format constant recovered from libisvcrypto.so
# (libisvcrypto.so, split_config.arm64_v8a.apk): nativeSignProof builds it
# from XOR-obfuscated 64-bit constants on the stack; it is the HMAC key
# for the App-Proof signature AND the AES-256-GCM key for "enc:" values.
# It is a fixed format constant of the app, not an account credential.
CRYPTO_KEY = b"Kp0Sj7EeiobgI1OsvH4bFvOTGG2JDIFx"
WORKER_BASE = "https://isvsoft-vpn-worker.isvsoft.workers.dev"
CATALOG_JSON_PARAM = "04a486d15a5045278fa8c8516329be04"
CATALOG_URL = (WORKER_BASE + "/api/app?json=" + CATALOG_JSON_PARAM
               + "&type=full")
SERVERS_URL = (WORKER_BASE + "/api/app?json=" + CATALOG_JSON_PARAM
               + "&type=servers")
USER_AGENT = "ISVSOFT-CloudSync/2.0"  # Le7/a sets this unconditionally.

# ---------------------------------------------------------------------------
# Pure-Python AES-256-GCM (stdlib only). Cross-checked against the
# `cryptography` package on 1,951 real enc: values + random round-trips.
# ---------------------------------------------------------------------------

def _gf_mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return r


def _gf_pow(a, e):
    r = 1
    while e:
        if e & 1:
            r = _gf_mul(r, a)
        a = _gf_mul(a, a)
        e >>= 1
    return r


def _sbox_val(x):
    inv = 0 if x == 0 else _gf_pow(x, 254)
    s = inv
    for i in (1, 2, 3, 4):
        s ^= ((inv << i) | (inv >> (8 - i))) & 0xFF
    return (s ^ 0x63) & 0xFF


_SBOX = bytes(_sbox_val(i) for i in range(256))


def _build_te():
    te = [[0] * 256 for _ in range(4)]
    for i in range(256):
        s = _SBOX[i]
        x2 = _gf_mul(s, 2)
        x3 = _gf_mul(s, 3)
        te[0][i] = (x2 << 24) | (s << 16) | (s << 8) | x3
        te[1][i] = (x3 << 24) | (x2 << 16) | (s << 8) | s
        te[2][i] = (s << 24) | (x3 << 16) | (x2 << 8) | s
        te[3][i] = (s << 24) | (s << 16) | (x3 << 8) | x2
    return te


_TE = _build_te()
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
         0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]


def _expand_key(key):
    w = [int.from_bytes(key[4 * i:4 * i + 4], "big") for i in range(8)]
    for i in range(8, 60):
        t = w[i - 1]
        if i % 8 == 0:
            t = ((_SBOX[(t >> 16) & 0xFF] << 24) | (_SBOX[(t >> 8) & 0xFF] << 16)
                 | (_SBOX[t & 0xFF] << 8) | _SBOX[(t >> 24) & 0xFF]) ^ (_RCON[i // 8 - 1] << 24)
        elif i % 8 == 4:
            t = (_SBOX[(t >> 24) & 0xFF] << 24) | (_SBOX[(t >> 16) & 0xFF] << 16) | \
                (_SBOX[(t >> 8) & 0xFF] << 8) | _SBOX[t & 0xFF]
        w.append(w[i - 8] ^ t)
    return w


def _encrypt_block(w, block):
    s = [int.from_bytes(block[4 * i:4 * i + 4], "big") for i in range(4)]
    for i in range(4):
        s[i] ^= w[i]
    for rnd in range(1, 14):
        t = [0] * 4
        t[0] = (_TE[0][(s[0] >> 24) & 0xFF] ^ _TE[1][(s[1] >> 16) & 0xFF]
                ^ _TE[2][(s[2] >> 8) & 0xFF] ^ _TE[3][s[3] & 0xFF] ^ w[4 * rnd])
        t[1] = (_TE[0][(s[1] >> 24) & 0xFF] ^ _TE[1][(s[2] >> 16) & 0xFF]
                ^ _TE[2][(s[3] >> 8) & 0xFF] ^ _TE[3][s[0] & 0xFF] ^ w[4 * rnd + 1])
        t[2] = (_TE[0][(s[2] >> 24) & 0xFF] ^ _TE[1][(s[3] >> 16) & 0xFF]
                ^ _TE[2][(s[0] >> 8) & 0xFF] ^ _TE[3][s[1] & 0xFF] ^ w[4 * rnd + 2])
        t[3] = (_TE[0][(s[3] >> 24) & 0xFF] ^ _TE[1][(s[0] >> 16) & 0xFF]
                ^ _TE[2][(s[1] >> 8) & 0xFF] ^ _TE[3][s[2] & 0xFF] ^ w[4 * rnd + 3])
        s = t
    out = bytearray(16)
    for i in range(4):
        v = ((_SBOX[(s[i] >> 24) & 0xFF] << 24)
             | (_SBOX[(s[(i + 1) % 4] >> 16) & 0xFF] << 16)
             | (_SBOX[(s[(i + 2) % 4] >> 8) & 0xFF] << 8)
             | _SBOX[s[(i + 3) % 4] & 0xFF]) ^ w[56 + i]
        out[4 * i:4 * i + 4] = v.to_bytes(4, "big")
    return bytes(out)


def _inc32(counter):
    return counter[:12] + ((int.from_bytes(counter[12:], "big") + 1) & 0xFFFFFFFF).to_bytes(4, "big")


def _gctr(w, icb, data):
    out = bytearray()
    ctr = icb
    for i in range(0, len(data), 16):
        ks = _encrypt_block(w, ctr)
        chunk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
        ctr = _inc32(ctr)
    return bytes(out)


def _ghash(h, aad, ct):
    def pad(b):
        return b + b"\x00" * ((-len(b)) % 16)
    data = (pad(aad) + pad(ct)
            + (len(aad) * 8).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big"))
    y = 0
    h_int = int.from_bytes(h, "big")
    for i in range(0, len(data), 16):
        y ^= int.from_bytes(data[i:i + 16], "big")
        z = 0
        v = h_int
        for j in range(128):
            if (y >> (127 - j)) & 1:
                z ^= v
            if v & 1:
                v = (v >> 1) ^ 0xE1000000000000000000000000000000
            else:
                v >>= 1
        y = z
    return y.to_bytes(16, "big")


class _AES256GCM:
    def __init__(self, key):
        if len(key) != 32:
            raise ValueError("AES-256 needs a 32-byte key")
        self.w = _expand_key(key)
        self.h = _encrypt_block(self.w, b"\x00" * 16)

    def encrypt(self, nonce, data, aad=b""):
        if len(nonce) != 12:
            raise ValueError("nonce must be 12 bytes")
        j0 = nonce + b"\x00\x00\x00\x01"
        ct = _gctr(self.w, _inc32(j0), data)
        tag = bytes(a ^ b for a, b in zip(_ghash(self.h, aad or b"", ct),
                                          _encrypt_block(self.w, j0)))
        return ct + tag

    def decrypt(self, nonce, data, aad=b""):
        if len(nonce) != 12 or len(data) < 16:
            raise ValueError("bad input")
        j0 = nonce + b"\x00\x00\x00\x01"
        ct, tag = data[:-16], data[-16:]
        expect = bytes(a ^ b for a, b in zip(_ghash(self.h, aad or b"", ct),
                                             _encrypt_block(self.w, j0)))
        if tag != expect:
            raise ValueError("tag mismatch")
        return _gctr(self.w, _inc32(j0), ct)


_GCM = _AES256GCM(CRYPTO_KEY)

# ---------------------------------------------------------------------------
# ISVCrypto (Kotlin wrapper) equivalents
# ---------------------------------------------------------------------------

class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _b64url_decode(body: str) -> bytes:
    compact = re.sub(r"[ \t\r\n]", "", body)
    if not compact or not re.fullmatch(r"[A-Za-z0-9\-_]+", compact):
        raise DecodeError("FORMAT_ERROR", "Se esperaba base64url tras 'enc:'.")
    try:
        return base64.urlsafe_b64decode(compact + "=" * (-len(compact) % 4))
    except (ValueError, binascii.Error) as exc:
        raise DecodeError("FORMAT_ERROR", "Base64url inválido tras 'enc:'.") from exc


def decrypt_token(token: str) -> str:
    """ISVCrypto.a(): one "enc:" token -> plaintext (AES-256-GCM)."""
    if not isinstance(token, str) or not token.startswith("enc:"):
        raise DecodeError("FORMAT_ERROR", "Se esperaba un valor 'enc:'.")
    raw = _b64url_decode(token[4:])
    if len(raw) < 28:
        raise DecodeError("DECRYPT_FAILED", "El valor 'enc:' es demasiado corto.")
    try:
        plain = _GCM.decrypt(raw[:12], raw[12:])
    except ValueError as exc:
        raise DecodeError("DECRYPT_FAILED", "El valor 'enc:' no descifra (tag GCM inválido).") from exc
    try:
        return plain.decode("utf-8")
    except UnicodeError as exc:
        raise DecodeError("DECRYPT_FAILED", "El valor 'enc:' no es UTF-8 válido.") from exc


def decrypt_value(value: str) -> str:
    """ISVCrypto.a() with the Kotlin up-to-5 nested-decrypt loop."""
    current = value.strip().strip('"').strip("'").strip()
    for _ in range(5):
        if not current.startswith("enc:"):
            return current
        current = decrypt_token(current)
    if current.startswith("enc:"):
        raise DecodeError("DECRYPT_FAILED", "El valor sigue cifrado tras 5 rondas.")
    return current


def encrypt_token(plaintext: str) -> str:
    """ISVCrypto.b(): plaintext -> "enc:" token (random 12-byte nonce)."""
    if not plaintext:
        return plaintext
    nonce = os.urandom(12)
    raw = nonce + _GCM.encrypt(nonce, plaintext.encode("utf-8"))
    return "enc:" + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def sign_proof(path: str, timestamp: int | None = None,
               nonce: str | None = None) -> dict:
    """ISVCrypto.c(): App-Proof headers for a request path (bare encoded
    path, WITHOUT the query string, e.g. "/api/app")."""
    if timestamp is None:
        timestamp = int(time.time())
    if nonce is None:
        nonce = uuid.uuid4().hex
    message = f"{timestamp}:{nonce}:{path}".encode("utf-8")
    signature = hmac.new(CRYPTO_KEY, message, hashlib.sha256).hexdigest()
    return {"X-ISV-Timestamp": str(timestamp),
            "X-ISV-Nonce": nonce,
            "X-ISV-Signature": signature}


# ---------------------------------------------------------------------------
# Catalog JSON handling
# ---------------------------------------------------------------------------

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


def _decrypt_walk(node, stats):
    if isinstance(node, dict):
        return {k: _decrypt_walk(v, stats) for k, v in node.items()}
    if isinstance(node, list):
        return [_decrypt_walk(v, stats) for v in node]
    if isinstance(node, str) and node.strip().startswith("enc:"):
        stats["total"] += 1
        try:
            out = decrypt_value(node)
        except DecodeError:
            stats["failed"].append(node[:80])
            return node
        stats["ok"] += 1
        return out
    return node


def decode(data: bytes | str) -> dict:
    """Decrypt a catalog response (live JSON or bundled asset JSON)."""
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8-sig")
        except UnicodeError as exc:
            raise DecodeError("FORMAT_ERROR", "La entrada no es UTF-8 válido.") from exc
    else:
        text = data
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    doc = _json(text)
    if not any(k in doc for k in ("servers", "tweaks", "settings", "meta")):
        raise DecodeError("WRONG_DOCUMENT", "No es un catálogo STR VIP Proxy.")
    stats = {"total": 0, "ok": 0, "failed": []}
    out = _decrypt_walk(doc, stats)
    if stats["failed"]:
        raise DecodeError("DECRYPT_FAILED",
                          f"{len(stats['failed'])} valor(es) 'enc:' no descifraron; "
                          f"el primero: {stats['failed'][0]}")
    return out


def run(file_bytes: bytes | str) -> str | None:
    """Offline API: complete decrypted catalog JSON or None."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


def summary(doc: dict) -> dict:
    """Counts only; never reproduces decrypted values."""
    servers = doc.get("servers")
    tweaks = doc.get("tweaks")
    settings = doc.get("settings") or {}
    meta = doc.get("meta") or {}
    return {
        "catalog_version": meta.get("serverVersion") or meta.get("version"),
        "servers": len(servers) if isinstance(servers, list) else None,
        "tweaks": len(tweaks) if isinstance(tweaks, list) else None,
        "settings_sections": sorted(settings.keys()) if isinstance(settings, dict) else None,
        "sections": sorted(doc.keys()),
    }


# ---------------------------------------------------------------------------
# Download (exact app request; transport fallback only on truncation)
# ---------------------------------------------------------------------------

def _https_url(url: str):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment):
        raise ValueError("invalid HTTPS URL")
    return parsed


class _HTTPSRedirect(HTTPRedirectHandler):
    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            _https_url(newurl)
        except ValueError:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _Truncated(Exception):
    def __init__(self, partial: bytes, expected):
        super().__init__("download truncated")
        self.partial = partial
        self.expected = expected


def _headers_for(url: str) -> dict:
    parsed = urlsplit(url)
    # The interceptor signs the encoded path WITHOUT the query string:
    # nativeSignProof receives OkHttp's encodedPath ("/api/app").
    path = parsed.path
    headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"}
    if "api/app" in path or "/app" in path:
        headers.update(sign_proof(path))
    return headers


def _read_response(response, expected=None):
    try:
        data = response.read(MAX_BYTES + 1)
    except IncompleteRead as exc:
        data = exc.partial or b""
        if expected is not None and len(data) >= expected:
            return data[:expected]
        raise _Truncated(data, expected) from exc
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La respuesta supera el límite de tamaño.")
    return data


def _get_plain(url, opener):
    req = Request(url, headers=_headers_for(url), method="GET")
    with opener.open(req, timeout=30) as response:
        if response.status != 200:
            raise DecodeError("DOWNLOAD_FAILED", "El endpoint no devolvió 200.")
        length = response.headers.get("Content-Length")
        expected = int(length) if length and length.isdigit() else None
        data = _read_response(response, expected)
        if expected is not None and len(data) != expected:
            raise _Truncated(data, expected)
        return data


def _get_curl_http2(url):
    """Transport fallback: same URL + headers, HTTP/2 via curl.

    The worker ignores Range and always answers 200 with the full body,
    so resuming by ranges cannot help here; HTTP/2 completes the ~487 KB
    response where plain HTTP/1.1 through some proxies truncates it.
    """
    headers = _headers_for(url)
    cmd = ["curl", "--http2", "-sS", "--max-time", "60"]
    for key, value in headers.items():
        cmd += ["-H", f"{key}: {value}"]
    cmd.append(url)
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=70)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DecodeError("DOWNLOAD_FAILED", "El fallback curl no pudo ejecutarse.") from exc
    if proc.returncode != 0 or not proc.stdout:
        raise DecodeError("DOWNLOAD_FAILED",
                          "El fallback curl no devolvió contenido.")
    return proc.stdout


def _maybe_gunzip(data: bytes) -> bytes:
    if data[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(data)
        except (OSError, EOFError) as exc:
            raise DecodeError("DOWNLOAD_TRUNCATED", "El cuerpo gzip está incompleto.") from exc
    return data


def fetch_catalog(url: str = CATALOG_URL) -> bytes:
    """Plain GET exactly as the app makes it; curl --http2 only if truncated."""
    _https_url(url)
    opener = build_opener(_HTTPSRedirect())
    last_error = None
    for _ in range(3):
        try:
            raw = _get_plain(url, opener)
        except _Truncated as exc:
            last_error = exc
            continue
        except (HTTPError, URLError, HTTPException, OSError, ValueError) as exc:
            code = "ACCESS_DENIED" if isinstance(exc, HTTPError) and exc.code in (401, 403) else "DOWNLOAD_FAILED"
            raise DecodeError(code, "No se pudo descargar el catálogo mediante HTTPS.") from exc
        # NOTE: gunzip is validated OUTSIDE the try above on purpose: a
        # truncated gzip body is a transport failure (retry / curl fallback),
        # not a hard download error. DecodeError is a ValueError subclass,
        # so checking it inside that try would convert it immediately.
        try:
            return _maybe_gunzip(raw)
        except DecodeError as exc:
            last_error = exc
            continue
    for _ in range(3):
        try:
            return _maybe_gunzip(_get_curl_http2(url))
        except DecodeError:
            continue
    if last_error is not None:
        raise DecodeError("DOWNLOAD_TRUNCATED",
                          "La descarga se cortó y no se pudo completar.") from last_error
    raise DecodeError("DOWNLOAD_FAILED", "No se pudo descargar el catálogo mediante HTTPS.")


def read_bundled(apk_path: Path) -> bytes:
    """Merge the three bundled assets into the live catalog shape."""
    try:
        with zipfile.ZipFile(apk_path) as zf:
            servers = json.loads(zf.read("assets/servers.json").decode("utf-8"))
            tweaks = json.loads(zf.read("assets/tweaks.json").decode("utf-8"))
            settings = json.loads(zf.read("assets/settings.json").decode("utf-8"))
    except (OSError, KeyError, zipfile.BadZipFile, ValueError) as exc:
        raise DecodeError("APK_ERROR", "No se pudieron leer los assets del APK.") from exc
    merged = {
        "meta": servers.get("meta", {}),
        "servers": servers.get("servers", []),
        "tweaks": tweaks.get("tweaks", []),
        "settings": {k: v for k, v in settings.items() if k != "meta"},
    }
    return json.dumps(merged, ensure_ascii=False).encode("utf-8")


def _read_file(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


def _write_output(path: Path, rendered: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, rendered.encode("utf-8"))
    finally:
        os.close(fd)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path,
                        help="Respuesta del catálogo guardada localmente")
    source.add_argument("--url", nargs="?", const=CATALOG_URL,
                        help="Descarga explícita; por defecto usa el endpoint original")
    source.add_argument("--servers", action="store_true",
                        help="Descarga el endpoint ligero type=servers")
    source.add_argument("--apks", type=Path, metavar="APK",
                        help="Lee los assets del APK indicado")
    source.add_argument("--stdin", action="store_true",
                        help="Lee la respuesta JSON desde stdin")
    parser.add_argument("-o", "--output", type=Path,
                        help="Guardar JSON completo; no sobrescribe")
    parser.add_argument("--summary", action="store_true",
                        help="Solo recuentos (versión y tamaños de lista), sin valores descifrados")
    args = parser.parse_args(argv)
    try:
        if args.servers:
            raw = fetch_catalog(SERVERS_URL)
        elif args.url is not None:
            raw = fetch_catalog(args.url)
        elif args.apks is not None:
            raw = read_bundled(args.apks)
        elif args.stdin:
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
        else:
            raw = _read_file(args.file)
        doc = decode(raw)
        if args.summary:
            rendered = json.dumps(summary(doc), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        else:
            rendered = json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            _write_output(args.output, rendered)
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
