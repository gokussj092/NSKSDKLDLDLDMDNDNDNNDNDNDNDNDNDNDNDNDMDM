#!/usr/bin/env python3
"""STR VIP Proxy (app.isvsoft.strvipproxy, versionCode 1, versionName 1.42.5):
.isc / .ovpn / .conf files, isv-config:// links, ISV- cloud codes and
VMess / VLESS / Trojan / Shadowsocks / WireGuard links.

Standalone Python 3.10+, standard library only, no network access except
for an explicit --cloud code fetch. For catalogs use STR_VIP_Proxy.py.

Flow verified by decompiling this APK (classes3.dex bytecode):
  * File import — LT6/F1.invokeSuspend (the "Import .isc File" flow):
    ContentResolver.openInputStream(Uri) -> whole file as UTF-8 text,
    trimmed. The file name must end with .isc, .txt, .json or .conf
    (case-insensitive), OR the content must start with "isv-config://"
    or "{". The text is then parsed by LT6/E.b (via the LT6/F coroutine).
  * LT6/E.b dispatch on the trimmed text:
      - starts with "isv-config://" -> strip the 13-char prefix, then
        LT6/E.a(payload);
      - starts with "{" -> LT6/E.d(text): Gson parses a SharedConfig;
      - otherwise -> LT6/E.a(text), then the same ISV- / "{" dispatch
        on the result.
  * LT6/E.a(s): ISVCrypto decrypt of the value (the value is used as an
    "enc:" token, prepending "enc:" when the prefix is missing); returns
    the plaintext only when it differs from the input and is not blank,
    else null.
  * LT6/E.d(json): Gson -> SharedConfig{protocol, locked, configJson,
    expirationDays, expirationTimestamp, burnAfterRead, message}; the
    configJson string is then parsed by LT6/E.c(protocol, configJson)
    into ProtocolConfig$Ssh / $OpenVpn / $V2Ray / $Hysteria (Gson,
    by protocol). This decoder returns the parsed configJson as a dict
    with every stored field, without enforcing the app's policies
    (locked / expiry / burn-after-read are reported, not enforced).
  * A result starting with "ISV-" is a cloud share code: the app looks
    it up in its local cache (two built-in demo codes, ISV-SSH-LOCK and
    ISV-OVPN-FREE, are pre-seeded in LT6/E.<clinit>) or fetches it from
    the worker (GET /api/v1/config/share/{code}, see fetch_shared_config
    below; verified live only for the not-found path: a bogus code
    returns 404 {"success": false, "error": "Shared config not found or
    expired."}). A bare ISV- code cannot be resolved offline, so
    decode() returns it as a share-code marker and --cloud fetches it.
  * "enc:" tokens use the same AES-256-GCM construction as the catalog
    (see STR_VIP_Proxy.py): "enc:" + base64url(nonce(12) || ciphertext
    || tag(16)), key = the 32-byte ASCII format constant recovered from
    libisvcrypto.so. The pure-Python AES-256-GCM below is the same code
    as in STR_VIP_Proxy.py, cross-checked against the `cryptography`
    package on all 1,951 enc: values of the live + bundled catalogs.
  * OpenVPN import is a separate path (libovpn3): the app accepts
    .ovpn/.conf files as plain OpenVPN config text and rejects ZIP
    archives ("Input looks like a ZIP Archive. Import is only possible
    for OpenVPN config files (.ovpn/.conf)"). This decoder parses the
    directives and inline blocks (<ca>, <cert>, <key>, <tls-auth>,
    <tls-crypt>, <connection>) without changing values.
  * Protocol links — ProtocolImportSheet ("Paste a VMess, VLESS,
    Trojan, Shadowsocks, or WireGuard link below"): standard URI formats
    parsed by the bundled V2Ray core library. This decoder implements
    the standard vmess:// (base64 JSON), vless://, trojan:// and ss://
    formats, plus standard WireGuard [Interface]/[Peer] config text
    (the exact WireGuard *link* spelling the app accepts could not be
    confirmed without a real sample; see README.md).
  * No .sks support: no reference to .sks exists in the manifest, the
    DEX strings or the import code. No decoder for it was built.
  * The manifest registers NO file association and NO custom URI scheme
    (MainActivity has only the launcher intent-filter); import happens
    from the in-app file picker / clipboard / link paste, not from the
    system opening a file with the app.

!!! No real .isc / .ovpn / isv-config:// sample exported by STR VIP Proxy
!!! 1.42.5 exists yet. The formats above are proven from the app's own
!!! code (bytecode-verified dispatch + native-library-verified crypto),
!!! and the self-test (--self-test) round-trips synthetic samples through
!!! the same code paths, but end-to-end confirmation against a real
!!! exported file is still pending (see README.md).
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
import sys
import time
import uuid
from http.client import HTTPException, IncompleteRead
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000

# Same 32-byte ASCII format constant as STR_VIP_Proxy.py (recovered from
# libisvcrypto.so; a fixed format constant, not an account credential).
CRYPTO_KEY = b"Kp0Sj7EeiobgI1OsvH4bFvOTGG2JDIFx"
WORKER_BASE = "https://isvsoft-vpn-worker.isvsoft.workers.dev"
USER_AGENT = "ISVSOFT-CloudSync/2.0"

# ---------------------------------------------------------------------------
# Pure-Python AES-256-GCM (stdlib only; identical to STR_VIP_Proxy.py)
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
# Errors, JSON helpers, ISVCrypto equivalents
# ---------------------------------------------------------------------------

class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


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


def _b64url_decode(body: str) -> bytes:
    compact = re.sub(r"[ \t\r\n]", "", body)
    if not compact or not re.fullmatch(r"[A-Za-z0-9\-_]+", compact):
        raise DecodeError("FORMAT_ERROR", "Se esperaba base64url.")
    try:
        return base64.urlsafe_b64decode(compact + "=" * (-len(compact) % 4))
    except (ValueError, binascii.Error) as exc:
        raise DecodeError("FORMAT_ERROR", "Base64url inválido.") from exc


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


def _try_decrypt_blob(blob: str) -> str | None:
    """LT6/E.a(): try ISVCrypto decrypt of a blob, with or without the
    "enc:" prefix. Returns the plaintext or None when it does not decrypt
    (or when the result is blank / identical to the input)."""
    candidates = [blob] if blob.startswith("enc:") else ["enc:" + blob]
    for candidate in candidates:
        try:
            out = decrypt_value(candidate)
        except DecodeError:
            continue
        if out != blob and out.strip():
            return out
    return None


# ---------------------------------------------------------------------------
# SharedConfig (.isc) handling
# ---------------------------------------------------------------------------

def _parse_shared_config(text: str) -> dict:
    """LT6/E.d + LT6/E.c: SharedConfig JSON -> resolved profile dict."""
    doc = _json(text)
    if "protocol" not in doc or "configJson" not in doc:
        raise DecodeError("WRONG_DOCUMENT",
                          "El JSON no es un SharedConfig (faltan protocol/configJson).")
    config = doc.get("configJson")
    if isinstance(config, str):
        try:
            config = _json(config)
        except DecodeError:
            pass  # keep the raw string; the app would fail the same way
    return {
        "format": "shared-config",
        "protocol": doc.get("protocol"),
        "locked": bool(doc.get("locked", False)),
        "config": config,
        "expirationDays": doc.get("expirationDays"),
        "expirationTimestamp": doc.get("expirationTimestamp"),
        "burnAfterRead": bool(doc.get("burnAfterRead", False)),
        "message": doc.get("message"),
    }


def _resolve_decrypted(text: str) -> dict:
    """Dispatch after a successful decrypt, mirroring LT6/E.b / LT6/F."""
    text = text.strip()
    if text.startswith("ISV-"):
        code = text.split()[0]
        return {"format": "isv-share-code", "share_code": code,
                "note": "Código de nube: usar --cloud para descargarlo del worker."}
    if text.startswith("{"):
        return _parse_shared_config(text)
    raise DecodeError("WRONG_DOCUMENT",
                      "El contenido descifrado no es un SharedConfig ni un código ISV-.")


def decode_shared_text(text: str) -> dict:
    """LT6/E.b on a trimmed text: isv-config://, JSON, enc: blob, ISV- code,
    or a bare base64 blob (defensive fallback for the "ey..." placeholder
    shown in the app's import sheet; the decompiled E.a is decrypt-only)."""
    text = text.strip()
    if not text:
        raise DecodeError("FORMAT_ERROR", "Entrada vacía.")
    if text.startswith("isv-config://"):
        payload = text[len("isv-config://"):].strip()
        if not payload:
            raise DecodeError("FORMAT_ERROR", "El enlace isv-config:// no trae contenido.")
        plain = _try_decrypt_blob(payload)
        if plain is not None:
            return _resolve_decrypted(plain)
        # Defensive fallback: base64url of the JSON itself.
        try:
            raw = _b64url_decode(payload)
            return _resolve_decrypted(raw.decode("utf-8"))
        except (DecodeError, UnicodeError):
            raise DecodeError("DECRYPT_FAILED",
                              "El enlace isv-config:// no descifra.") from None
    if text.startswith("ISV-"):
        code = text.split()[0]
        return {"format": "isv-share-code", "share_code": code,
                "note": "Código de nube: usar --cloud para descargarlo del worker."}
    if text.startswith("{"):
        return _parse_shared_config(text)
    plain = _try_decrypt_blob(text)
    if plain is not None:
        return _resolve_decrypted(plain)
    try:
        raw = _b64url_decode(text)
        return _resolve_decrypted(raw.decode("utf-8"))
    except (DecodeError, UnicodeError):
        raise DecodeError("FORMAT_ERROR",
                          "No es un SharedConfig, un enlace isv-config://, un valor "
                          "'enc:' ni un código ISV- válido.") from None


# ---------------------------------------------------------------------------
# Cloud share code fetch
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


def fetch_shared_config(code: str) -> dict:
    """GET /api/v1/config/share/{code} on the worker (the app's
    fetchSharedConfigFromCloud). Only the not-found path was verified
    live (404 {"success": false, "error": "Shared config not found or
    expired."}); the success shape below follows SharedConfigGetResponse
    (success, shareId, shareCode, shareName, author, protocol,
    configData) and is UNCONFIRMED without a real code. No App-Proof
    headers are sent: the endpoint answers with its own JSON error
    without them."""
    code = code.strip()
    if not re.fullmatch(r"ISV-[A-Za-z0-9\-_]+", code):
        raise DecodeError("FORMAT_ERROR", "El código debe empezar por 'ISV-'.")
    url = f"{WORKER_BASE}/api/v1/config/share/{code}"
    _https_url(url)
    req = Request(url, headers={"User-Agent": USER_AGENT,
                                "Accept-Encoding": "gzip"}, method="GET")
    opener = build_opener(_HTTPSRedirect())
    try:
        with opener.open(req, timeout=30) as response:
            raw = response.read(MAX_BYTES + 1)
            if response.headers.get("Content-Encoding") == "gzip":
                raw = gzip.decompress(raw)
    except HTTPError as exc:
        try:
            body = exc.read(MAX_BYTES + 1)
            if exc.headers.get("Content-Encoding") == "gzip":
                body = gzip.decompress(body)
            detail = json.loads(body.decode("utf-8"))
            message = detail.get("error") or detail.get("message") or f"HTTP {exc.code}"
        except (ValueError, UnicodeError, OSError, EOFError):
            message = f"HTTP {exc.code}"
        raise DecodeError("DOWNLOAD_FAILED", f"No se pudo descargar el código: {message}") from exc
    except (URLError, HTTPException, OSError, ValueError) as exc:
        raise DecodeError("DOWNLOAD_FAILED", "No se pudo contactar el worker.") from exc
    try:
        doc = _json(raw.decode("utf-8"))
    except (DecodeError, UnicodeError) as exc:
        raise DecodeError("INVALID_JSON", "La respuesta del worker no es JSON válido.") from exc
    if not doc.get("success"):
        raise DecodeError("DOWNLOAD_FAILED",
                          f"El worker rechazó el código: {doc.get('error') or doc.get('message') or 'sin detalle'}")
    config_data = doc.get("configData")
    protocol = doc.get("protocol")
    if isinstance(config_data, str):
        try:
            inner = _json(config_data)
        except DecodeError:
            inner = None
        if isinstance(inner, dict) and "configJson" in inner:
            return _parse_shared_config(config_data)
        if isinstance(inner, dict):
            return {"format": "shared-config", "protocol": protocol,
                    "locked": False, "config": inner,
                    "expirationDays": None, "expirationTimestamp": None,
                    "burnAfterRead": False, "message": doc.get("shareName")}
    return {"format": "shared-config", "protocol": protocol,
            "locked": False, "config": config_data,
            "expirationDays": None, "expirationTimestamp": None,
            "burnAfterRead": False, "message": doc.get("shareName")}


# ---------------------------------------------------------------------------
# OpenVPN (.ovpn / .conf) parsing
# ---------------------------------------------------------------------------

_INLINE_BLOCKS = ("ca", "cert", "key", "tls-auth", "tls-crypt",
                  "tls-crypt-v2", "auth-user-pass", "static-key")


def _parse_openvpn(text: str) -> dict:
    """Plain OpenVPN config text -> structured dict (directives + inline
    blocks + <connection> sections). Values are kept verbatim."""
    if text.startswith("PK\x03\x04"):
        raise DecodeError("FORMAT_ERROR",
                          "Es un archivo ZIP; la app solo importa .ovpn/.conf "
                          "de texto plano.")
    lines = text.splitlines()
    directives: dict[str, object] = {}
    inline: dict[str, str] = {}
    connections: list[dict] = []
    remotes: list[str] = []
    current_block: str | None = None
    block_lines: list[str] = []
    current_conn: dict | None = None

    def store(key: str, value: str):
        nonlocal current_conn
        target = current_conn if current_conn is not None else directives
        if key == "remote":
            remotes.append(value)
        if key in target:
            existing = target[key]
            target[key] = existing + [value] if isinstance(existing, list) else [existing, value]
        else:
            target[key] = value

    for raw_line in lines:
        line = raw_line.strip()
        if current_block is not None:
            if line == f"</{current_block}>":
                inline[current_block] = "\n".join(block_lines)
                current_block = None
                block_lines = []
            else:
                block_lines.append(raw_line.rstrip("\n"))
            continue
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("<") and line.endswith(">") and not line.startswith("</"):
            name = line[1:-1].strip().lower()
            if name == "connection":
                current_conn = {}
                connections.append(current_conn)
            elif name in _INLINE_BLOCKS:
                current_block = name
                block_lines = []
            continue
        if line.startswith("</"):
            if line == "</connection>":
                current_conn = None
            continue
        parts = line.split(None, 1)
        key = parts[0]
        value = parts[1].strip() if len(parts) > 1 else ""
        store(key, value)
    if current_block is not None:
        raise DecodeError("FORMAT_ERROR", f"Bloque <{current_block}> sin cerrar.")
    if not directives and not inline and not connections:
        raise DecodeError("WRONG_DOCUMENT", "No parece una configuración OpenVPN.")
    return {"format": "openvpn", "directives": directives,
            "inline": inline, "remotes": remotes, "connections": connections}


# ---------------------------------------------------------------------------
# Standard protocol links (vmess / vless / trojan / ss) + WireGuard text
# ---------------------------------------------------------------------------

def _b64_decode_loose(text: str) -> bytes:
    compact = re.sub(r"[ \t\r\n]", "", text)
    try:
        return base64.urlsafe_b64decode(compact + "=" * (-len(compact) % 4))
    except (ValueError, binascii.Error) as exc:
        raise DecodeError("FORMAT_ERROR", "Base64 inválido en el enlace.") from exc


def _parse_vmess(link: str) -> dict:
    try:
        doc = _json(_b64_decode_loose(link[len("vmess://"):]).decode("utf-8"))
    except (DecodeError, UnicodeError) as exc:
        raise DecodeError("FORMAT_ERROR", "El enlace vmess:// no trae JSON base64 válido.") from exc
    return {"format": "vmess", "name": doc.get("ps"), "address": doc.get("add"),
            "port": doc.get("port"), "uuid": doc.get("id"), "alterId": doc.get("aid"),
            "network": doc.get("net"), "type": doc.get("type"), "host": doc.get("host"),
            "path": doc.get("path"), "tls": doc.get("tls"),
            "security": doc.get("scy"), "sni": doc.get("sni")}


def _parse_vless_trojan(link: str) -> dict:
    scheme = "vless" if link.startswith("vless://") else "trojan"
    rest = link.split("://", 1)[1]
    if "#" in rest:
        rest, tag = rest.rsplit("#", 1)
        name = unquote(tag)
    else:
        name = ""
    if "@" not in rest:
        raise DecodeError("FORMAT_ERROR", f"El enlace {scheme}:// no trae usuario@servidor.")
    userinfo, _, hostport = rest.rpartition("@")
    if "?" in hostport:
        hostport, _, query = hostport.partition("?")
        params = dict(part.split("=", 1) for part in query.split("&") if "=" in part)
    else:
        params = {}
    if ":" in hostport:
        host, _, port = hostport.rpartition(":")
    else:
        host, port = hostport, ""
    out = {"format": scheme, "name": name, "address": unquote(host),
           "port": port, "params": {k: unquote(v) for k, v in params.items()}}
    if scheme == "vless":
        out["uuid"] = unquote(userinfo)
    else:
        out["password"] = unquote(userinfo)
    return out


def _parse_shadowsocks(link: str) -> dict:
    rest = link[len("ss://"):]
    if "#" in rest:
        rest, tag = rest.rsplit("#", 1)
        name = unquote(tag)
    else:
        name = ""
    if "@" in rest:
        userinfo_b64, _, hostport = rest.rpartition("@")
        try:
            userinfo = _b64_decode_loose(userinfo_b64).decode("utf-8")
        except (DecodeError, UnicodeError):
            userinfo = unquote(userinfo_b64)
    else:
        try:
            decoded = _b64_decode_loose(rest.split("?")[0]).decode("utf-8")
        except (DecodeError, UnicodeError) as exc:
            raise DecodeError("FORMAT_ERROR", "El enlace ss:// no trae credenciales base64 válidas.") from exc
        if "@" not in decoded:
            raise DecodeError("FORMAT_ERROR", "El enlace ss:// no trae método:clave@servidor.")
        userinfo, _, hostport = decoded.rpartition("@")
    if ":" not in userinfo:
        raise DecodeError("FORMAT_ERROR", "El enlace ss:// no trae método:clave.")
    method, _, password = userinfo.partition(":")
    if "?" in hostport:
        hostport, _, query = hostport.partition("?")
        params = dict(part.split("=", 1) for part in query.split("&") if "=" in part)
    else:
        params = {}
    if ":" in hostport:
        host, _, port = hostport.rpartition(":")
    else:
        host, port = hostport, ""
    return {"format": "shadowsocks", "name": name, "method": method,
            "password": password, "address": unquote(host), "port": port,
            "params": {k: unquote(v) for k, v in params.items()}}


def _parse_wireguard(text: str) -> dict:
    """Standard WireGuard [Interface]/[Peer] config text."""
    sections: dict[str, dict[str, str]] = {}
    current: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            sections.setdefault(current, {})
            continue
        if current is None or "=" not in line:
            continue
        key, _, value = line.partition("=")
        sections[current][key.strip()] = value.strip()
    if "Interface" not in sections or "Peer" not in sections:
        raise DecodeError("WRONG_DOCUMENT",
                          "No es una configuración WireGuard ([Interface]/[Peer]).")
    return {"format": "wireguard", "interface": sections["Interface"],
            "peer": sections["Peer"],
            "extra_sections": {k: v for k, v in sections.items()
                               if k not in ("Interface", "Peer")}}


# ---------------------------------------------------------------------------
# decode() / run() dispatch (mirrors the app's import entry points)
# ---------------------------------------------------------------------------

def decode(data: bytes | str) -> dict:
    """Decode one STR VIP Proxy input: .isc/.txt/.json/.conf text, an
    isv-config:// link, a bare ISV- cloud code, a vmess/vless/trojan/ss
    link, a WireGuard config text, or a plain OpenVPN (.ovpn/.conf) text.
    Returns the resolved profile/config dict; share codes resolve to a
    marker (fetch with --cloud)."""
    text = _text(data)
    if text.startswith("PK\x03\x04"):
        raise DecodeError("FORMAT_ERROR",
                          "Es un archivo ZIP; la app solo importa .ovpn/.conf "
                          "de texto plano.")
    lowered = text.lower()
    if lowered.startswith(("vmess://", "vless://", "trojan://", "ss://")):
        if lowered.startswith("vmess://"):
            return _parse_vmess(text)
        if lowered.startswith(("vless://", "trojan://")):
            return _parse_vless_trojan(text)
        return _parse_shadowsocks(text)
    if "[interface]" in lowered and "[peer]" in lowered:
        return _parse_wireguard(text)
    if text.startswith(("isv-config://", "ISV-", "{", "enc:")) or \
            re.fullmatch(r"[A-Za-z0-9\-_]+={0,2}", text):
        return decode_shared_text(text)
    return _parse_openvpn(text)


def run(file_bytes: bytes | str) -> str | None:
    """Offline API: decoded profile/config JSON or None."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


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


# ---------------------------------------------------------------------------
# Self-test (synthetic round-trips; no real exported file exists yet)
# ---------------------------------------------------------------------------

def _self_test() -> int:
    cases = []
    # 1. SharedConfig SSH as plain JSON
    ssh = {"protocol": "SSH", "locked": True,
           "configJson": json.dumps({"host": "ssh.isvsoft.xyz", "port": 22,
                                     "username": "premium_user",
                                     "password": "locked_password_123",
                                     "payload": "GET / HTTP/1.1\r\nHost: line.me\r\n\r\n",
                                     "tunnelMode": "SSL"}, ensure_ascii=False),
           "expirationDays": 120, "expirationTimestamp": 0,
           "burnAfterRead": False, "message": ""}
    cases.append(("isc-json", json.dumps(ssh, ensure_ascii=False), ssh["protocol"]))
    # 2. Same config encrypted as an isv-config:// link (ISVCrypto.b)
    link = "isv-config://" + encrypt_token(json.dumps(ssh, ensure_ascii=False))
    cases.append(("isv-config-enc", link, ssh["protocol"]))
    # 3. Bare enc: blob of the same JSON
    cases.append(("bare-enc", encrypt_token(json.dumps(ssh, ensure_ascii=False)), ssh["protocol"]))
    # 4. base64url of the JSON after isv-config:// (defensive path)
    b64 = base64.urlsafe_b64encode(json.dumps(ssh, ensure_ascii=False).encode()).decode().rstrip("=")
    cases.append(("isv-config-b64", "isv-config://" + b64, ssh["protocol"]))
    # 5. OpenVPN config text
    ovpn = ("client\ndev tun\nproto tcp\nremote vpn.example.com 443\n"
            "auth-user-pass\n<ca>\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n</ca>\n"
            "<auth-user-pass>\nuser1\npass1\n</auth-user-pass>\n")
    cases.append(("ovpn", ovpn, "openvpn"))
    # 6. Standard protocol links
    vmess = {"v": "2", "ps": "Test", "add": "1.2.3.4", "port": "443",
             "id": "11111111-2222-3333-4444-555555555555", "aid": "0",
             "net": "ws", "type": "none", "host": "example.com",
             "path": "/ws", "tls": "tls"}
    cases.append(("vmess", "vmess://" + base64.urlsafe_b64encode(
        json.dumps(vmess).encode()).decode().rstrip("="), "vmess"))
    cases.append(("vless", "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443"
                  "?encryption=none&security=tls&sni=example.com&type=ws#Test", "vless"))
    cases.append(("trojan", "trojan://password123@1.2.3.4:443?sni=example.com#Test", "trojan"))
    ss_raw = "aes-256-gcm:secret@1.2.3.4:8388"
    cases.append(("ss", "ss://" + base64.urlsafe_b64encode(ss_raw.encode()).decode().rstrip("=")
                  + "#Test", "shadowsocks"))
    # 7. WireGuard config text
    wg = ("[Interface]\nPrivateKey = AAAA\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\n\n"
          "[Peer]\nPublicKey = BBBB\nAllowedIPs = 0.0.0.0/0\nEndpoint = 1.2.3.4:51820\n")
    cases.append(("wireguard", wg, "wireguard"))
    # 8. Bare share code marker
    cases.append(("share-code", "ISV-TEST-123", "isv-share-code"))

    passed = 0
    failed = []
    for name, payload, want in cases:
        try:
            out = decode(payload)
            if want == "SSH":
                ok = (out.get("format") == "shared-config"
                      and out.get("protocol") == "SSH"
                      and isinstance(out.get("config"), dict)
                      and out["config"].get("host") == "ssh.isvsoft.xyz")
            else:
                ok = out.get("format") == want
            if ok:
                passed += 1
            else:
                failed.append((name, f"format={out.get('format')}"))
        except DecodeError as exc:
            failed.append((name, f"{exc.code}: {exc}"))
    # 9. Tampered enc: must fail
    tampered = encrypt_token('{"protocol": "SSH", "configJson": "{}"}')
    bad = tampered[:-2] + ("AA" if tampered[-2:] != "AA" else "BB")
    try:
        decode(bad)
        failed.append(("tamper", "accepted a tampered token"))
    except DecodeError:
        passed += 1
    total = len(cases) + 1
    print(json.dumps({"self_test": "pass" if passed == total else "fail",
                      "cases": total, "passed": passed,
                      "failed": failed}, ensure_ascii=False))
    return 0 if passed == total else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path,
                        help="Archivo .isc/.txt/.json/.conf/.ovpn o texto guardado")
    source.add_argument("--text", help="Contenido o enlace a decodificar")
    source.add_argument("--cloud", metavar="CODE",
                        help="Descarga un código ISV- del worker y lo decodifica")
    source.add_argument("--self-test", action="store_true",
                        help="Round-trips sintéticos; no usa archivos reales")
    parser.add_argument("-o", "--output", type=Path,
                        help="Guardar JSON completo; no sobrescribe")
    parser.add_argument("--summary", action="store_true",
                        help="Solo formato y claves, sin valores descifrados")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    try:
        if args.cloud is not None:
            doc = fetch_shared_config(args.cloud)
        else:
            doc = decode(args.text if args.text is not None else _read_file(args.file))
        if args.summary:
            rendered = json.dumps(
                {"format": doc.get("format"),
                 "protocol": doc.get("protocol"),
                 "fields": sorted(doc.keys())},
                ensure_ascii=False, indent=2, allow_nan=False) + "\n"
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
