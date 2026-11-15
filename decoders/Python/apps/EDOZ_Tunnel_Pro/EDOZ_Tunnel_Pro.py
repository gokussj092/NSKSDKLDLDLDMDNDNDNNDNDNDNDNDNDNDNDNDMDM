#!/usr/bin/env python3
"""Edoztunnel Pro 2.4 (net.androidtechvilla.edoztunnelpro): catalog decoder.

Method (verified in this APK, versionCode 15):
  * Catalog (free): GET the GitHub raw URL below with Apache
    DefaultHttpClient (l5/h.java) -- plain GET, no headers of its own.
    The server returns the same body for any User-Agent (verified live).
  * Body: one Base64 line -> OpenSSL "Salted__" container ->
    EVP_BytesToKey/MD5 -> AES-256-CBC/PKCS#7 -> JSON.
    Passphrase: "securedjson" (p5/f.java, f8815a; shared OpenSSL format
    passphrase, not an account credential). The app's decryptor is
    org.apache.commons.ssl.OpenSSL.decrypt("aes256", ...); the same
    code also opens the APK-bundled assets/defconf (Version 23.08).
  * VIP catalog: same host, "Edoztunnel Pro VIP V3" URL (p5/d.java,
    field d, built from bytes). It is fetched the same way and stored
    in the same SQLite cache (m5/a.java, row 2) to be decrypted with
    the same passphrase -- but the live VIP file does NOT decrypt
    (see VIP_DECRYPT_FAILED below). This script never invents VIP
    servers: --vip reports the failure with the evidence.
  * Catalog JSON keys: Version, Message, Servers[], Tweaks[].
    Servers have no premium/free marker in the free catalog (all 23
    are free). Tweaks are the payload entries.
  * No own importable file format: the manifest has no ACTION_VIEW
    intent-filter and no own URI scheme; the app only builds standard
    .ovpn configs internally (assets/udp template, OpenVPN ClientAPI),
    which SP-DECODE already decodes. There is no
    EDOZ_Tunnel_Pro_archivos.py for this reason.
  * No own text URI scheme (no edoz:// or similar in the manifest).

Pure Python 3.10+ stdlib only (AES-256-CBC implemented in-file and
verified byte-for-byte against PyCryptodome with the real catalog).

Live test (2026-11-13): free catalog HTTP 200, 1,036,137 bytes,
Version 50.8, 23 servers, 1558 tweaks. Bundled asset: Version 23.08,
20 servers, 900 tweaks.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import re
import struct
import sys
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
CATALOG_URL = (
    "https://raw.githubusercontent.com/chrisrepair/Updates/main/"
    "Edoztunnel%20Pro%20V7%202024"
)
VIP_CATALOG_URL = (
    "https://raw.githubusercontent.com/chrisrepair/Updates/main/"
    "Edoztunnel%20Pro%20VIP%20V3"
)
# The app fetches with Apache DefaultHttpClient (l5/h.java) and sets no
# headers of its own; this is the User-Agent that stack sends implicitly.
# The server returns the same body for any User-Agent (verified live).
USER_AGENT = "Apache-HttpClient/UNAVAILABLE (java 1.4)"
# Shared OpenSSL format passphrase from p5/f.java, not an account credential.
CATALOG_PASSPHRASE = b"securedjson"
LIST_FIELDS = ("Servers", "Tweaks")


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------- pure AES-256
def _make_sbox():
    sbox = []
    for i in range(256):
        if i == 0:
            inv = 0
        else:
            inv = None
            for y in range(1, 256):
                p = 0
                aa, bb = i, y
                while bb:
                    if bb & 1:
                        p ^= aa
                    aa = ((aa << 1) ^ (0x1b if aa & 0x80 else 0)) & 0xff
                    bb >>= 1
                if p == 1:
                    inv = y
                    break
        s = inv ^ ((inv << 1) | (inv >> 7)) ^ ((inv << 2) | (inv >> 6)) \
            ^ ((inv << 3) | (inv >> 5)) ^ ((inv << 4) | (inv >> 4)) ^ 0x63
        sbox.append(s & 0xff)
    return sbox


_SBOX = _make_sbox()
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _xtime(x):
    return ((x << 1) ^ (0x1b if x & 0x80 else 0)) & 0xff


def _gmul(x, n):
    """Multiply x by n in GF(2^8) for the small constants AES needs."""
    r = 0
    a, b = x, n
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


_MUL9 = [_gmul(i, 9) for i in range(256)]
_MUL11 = [_gmul(i, 11) for i in range(256)]
_MUL13 = [_gmul(i, 13) for i in range(256)]
_MUL14 = [_gmul(i, 14) for i in range(256)]


def _aes_key_expand(key):
    w = [x for grp in (struct.unpack(">4I", key[i:i + 16])
                       for i in range(0, 32, 16)) for x in grp]
    for i in range(8, 60):
        temp = w[i - 1]
        if i % 8 == 0:
            rot = ((temp << 8) | (temp >> 24)) & 0xffffffff
            sub = (_SBOX[(rot >> 24) & 0xff] << 24) | (_SBOX[(rot >> 16) & 0xff] << 16) \
                | (_SBOX[(rot >> 8) & 0xff] << 8) | _SBOX[rot & 0xff]
            temp = sub ^ (_RCON[i // 8 - 1] << 24)
        elif i % 8 == 4:
            temp = (_SBOX[(temp >> 24) & 0xff] << 24) | (_SBOX[(temp >> 16) & 0xff] << 16) \
                | (_SBOX[(temp >> 8) & 0xff] << 8) | _SBOX[temp & 0xff]
        w.append(w[i - 8] ^ temp)
    return w


def _aes_decrypt_block(key_words, block):
    """One AES-256 block, inverse cipher, state as 16 bytes column-major."""
    s = bytearray(block)
    rk = key_words
    for i in range(4):
        for j in range(4):
            s[4 * i + j] ^= (rk[56 + i] >> (24 - 8 * j)) & 0xff
    for rnd in range(13, 0, -1):
        # InvShiftRows: row r shifts RIGHT by r (new[c][r] = old[(c-r)%4][r]).
        t = bytearray(s)
        for r in range(4):
            for c in range(4):
                s[4 * c + r] = t[4 * ((c - r) % 4) + r]
        # InvSubBytes
        for i in range(16):
            s[i] = _INV_SBOX[s[i]]
        # AddRoundKey
        for i in range(4):
            for j in range(4):
                s[4 * i + j] ^= (rk[4 * rnd + i] >> (24 - 8 * j)) & 0xff
        # InvMixColumns
        for c in range(4):
            a0, a1, a2, a3 = s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]
            s[4 * c] = _MUL14[a0] ^ _MUL11[a1] ^ _MUL13[a2] ^ _MUL9[a3]
            s[4 * c + 1] = _MUL9[a0] ^ _MUL14[a1] ^ _MUL11[a2] ^ _MUL13[a3]
            s[4 * c + 2] = _MUL13[a0] ^ _MUL9[a1] ^ _MUL14[a2] ^ _MUL11[a3]
            s[4 * c + 3] = _MUL11[a0] ^ _MUL13[a1] ^ _MUL9[a2] ^ _MUL14[a3]
    # Final round: InvShiftRows, InvSubBytes, AddRoundKey(0)
    t = bytearray(s)
    for r in range(4):
        for c in range(4):
            s[4 * c + r] = t[4 * ((c - r) % 4) + r]
    for i in range(16):
        s[i] = _INV_SBOX[s[i]]
    for i in range(4):
        for j in range(4):
            s[4 * i + j] ^= (rk[i] >> (24 - 8 * j)) & 0xff
    return bytes(s)


def _aes_encrypt_block(key_words, block):
    """One AES-256 block, forward cipher (only used by --self-test)."""
    s = list(struct.unpack(">4I", block))
    rk = key_words
    for i in range(4):
        s[i] ^= rk[i]
    for rnd in range(1, 14):
        b = bytearray(16)
        for i in range(4):
            for j in range(4):
                b[4 * j + i] = _SBOX[(s[j] >> (24 - 8 * i)) & 0xff]
        sb = bytearray(16)
        for r in range(4):
            for c in range(4):
                sb[4 * c + r] = b[4 * ((c + r) % 4) + r]
        out = [0] * 4
        for c in range(4):
            a0, a1, a2, a3 = sb[4 * c], sb[4 * c + 1], sb[4 * c + 2], sb[4 * c + 3]
            out[c] = (_xtime(a0) ^ (_xtime(a1) ^ a1) ^ a2 ^ a3) << 24 \
                | (a0 ^ _xtime(a1) ^ (_xtime(a2) ^ a2) ^ a3) << 16 \
                | (a0 ^ a1 ^ _xtime(a2) ^ (_xtime(a3) ^ a3)) << 8 \
                | ((_xtime(a0) ^ a0) ^ a1 ^ a2 ^ _xtime(a3))
        s = out
        for i in range(4):
            s[i] ^= rk[4 * rnd + i]
    b = bytearray(16)
    for i in range(4):
        for j in range(4):
            b[4 * j + i] = _SBOX[(s[j] >> (24 - 8 * i)) & 0xff]
    sb = bytearray(16)
    for r in range(4):
        for c in range(4):
            sb[4 * c + r] = b[4 * ((c + r) % 4) + r]
    s = list(struct.unpack(">4I", bytes(sb)))
    for i in range(4):
        s[i] ^= rk[56 + i]
    return struct.pack(">4I", *s)


def _aes_cbc_decrypt(key, iv, data):
    if len(data) % 16:
        raise ValueError("ciphertext is not a whole number of AES blocks")
    kw = _aes_key_expand(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        dec = _aes_decrypt_block(kw, block)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = block
    return bytes(out)


def _aes_cbc_encrypt(key, iv, data):
    kw = _aes_key_expand(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        enc = _aes_encrypt_block(kw, block)
        out += enc
        prev = enc
    return bytes(out)


def _evp_bytes_to_key(password, salt):
    """OpenSSL EVP_BytesToKey with MD5: 32-byte key + 16-byte IV."""
    material, previous = b"", b""
    while len(material) < 48:
        previous = hashlib.md5(previous + password + salt).digest()
        material += previous
    return material[:32], material[32:48]


def _unpad(data):
    if not data:
        raise ValueError("empty plaintext")
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad PKCS#7 padding")
    return data[:-pad]


# ------------------------------------------------------------- text / JSON
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
        raise DecodeError("FORMAT_ERROR", "No es UTF-8 válido.") from exc
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
    # The live catalog contains literal control characters inside string
    # values (e.g. a raw newline in a payload); the app's parser accepts
    # them, so strict=False mirrors what the app reads.
    try:
        doc = json.loads(data, object_pairs_hook=_unique, parse_constant=_nonfinite,
                         strict=False)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("INVALID_JSON", "JSON inválido o con claves duplicadas.") from exc
    if not isinstance(doc, dict):
        raise DecodeError("WRONG_DOCUMENT", "El catálogo debe contener un objeto JSON.")
    return _validate(doc)


def decrypt_catalog_text(data: bytes | str) -> str:
    text = _text(data)
    if text.startswith("{"):
        return text  # p5/f.a returns plaintext unchanged if OpenSSL fails.
    raw = _base64(text)
    if not raw.startswith(b"Salted__"):
        raise DecodeError(
            "FORMAT_ERROR",
            "Se esperaba el contenedor OpenSSL Salted__ del catálogo "
            "(el cuerpo no empieza por Salted__; puede ser otro formato "
            "o un catálogo vacío).")
    if len(raw) < 32 or (len(raw) - 16) % 16:
        raise DecodeError("TRUNCATED", "El catálogo contiene bloques AES incompletos.")
    salt = raw[8:16]
    key, iv = _evp_bytes_to_key(CATALOG_PASSPHRASE, salt)
    try:
        plain = _unpad(_aes_cbc_decrypt(key, iv, raw[16:]))
        return plain.decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("DECRYPT_FAILED", "No se pudo descifrar este catálogo.") from exc


def decode(data: bytes | str) -> dict:
    doc = _json(decrypt_catalog_text(data))
    if not any(field in doc for field in LIST_FIELDS):
        raise DecodeError("WRONG_DOCUMENT", "No hay listas de servidores o tweaks en el catálogo.")
    for field in LIST_FIELDS:
        if field in doc and (not isinstance(doc[field], list)
                             or any(not isinstance(v, dict) for v in doc[field])):
            raise DecodeError("WRONG_DOCUMENT", "Las listas de catálogo deben contener objetos completos.")
    return doc


def summary(doc: dict) -> dict:
    """Counts only: version plus the length of each catalog list. No values."""
    out = {"Version": doc.get("Version")}
    for field in LIST_FIELDS:
        if field in doc:
            out[field] = len(doc[field])
    return out


def run(file_bytes: bytes | str) -> str | None:
    """Offline API: complete catalog JSON or None; never a partial list."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


# ------------------------------------------------------------- fetching
class _HTTPSRedirect(HTTPRedirectHandler):
    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlsplit(newurl)
        if parsed.scheme != "https" or parsed.username is not None or parsed.password is not None:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_catalog(url: str) -> bytes:
    """Plain GET exactly as the app does it (l5/h.java): no own headers,
    Apache DefaultHttpClient stack. urllib reads the proxy from the
    environment, as the other catalog scripts do."""
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None \
            or parsed.password is not None or parsed.fragment:
        raise DecodeError("BAD_URL", "Solo se permite una URL https sin credenciales.")
    opener = build_opener(_HTTPSRedirect)
    req = Request(url, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"})
    try:
        with opener.open(req, timeout=60) as resp:
            if resp.status != 200:
                raise DecodeError("HTTP_%d" % resp.status, "El servidor devolvió HTTP %d." % resp.status)
            body = resp.read(MAX_BYTES + 1)
    except HTTPError as exc:
        raise DecodeError("HTTP_%d" % exc.code, "El servidor devolvió HTTP %d." % exc.code) from exc
    except (URLError, HTTPException, TimeoutError, OSError) as exc:
        raise DecodeError("NETWORK", "No se pudo descargar el catálogo: %s" % exc) from exc
    if len(body) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El catálogo supera el límite de tamaño.")
    return body


# ------------------------------------------------------------- self-test
def _self_test() -> int:
    failures = []

    def check(name, ok, detail=""):
        print(("OK  " if ok else "FAIL") + " " + name + ((" -- " + detail) if detail else ""))
        if not ok:
            failures.append(name)

    # 1. Synthetic round-trip with a fixed salt (offline, no asset needed).
    try:
        doc = {"Version": "self-test", "Message": "ok",
               "Servers": [{"Name": "Test 1", "SSHHost": "127.0.0.1"}],
               "Tweaks": [{"Name": "Payload de prueba", "Payload": "GET / HTTP/1.1"}]}
        plain = json.dumps(doc, ensure_ascii=False).encode("utf-8")
        pad = 16 - len(plain) % 16
        plain += bytes([pad]) * pad
        salt = b"selftest"
        key, iv = _evp_bytes_to_key(CATALOG_PASSPHRASE, salt)
        blob = b"Salted__" + salt + _aes_cbc_encrypt(key, iv, plain)
        got = decode(base64.b64encode(blob).decode())
        check("round-trip sintetico", got == doc, "Version=%s" % got.get("Version"))
    except Exception as exc:  # noqa: BLE001 - self-test must report, not crash
        check("round-trip sintetico", False, repr(exc))

    # 2. Bundled asset assets/defconf (Version 23.08, 20 servers, 900 tweaks).
    asset = Path(__file__).with_name("defconf")
    if asset.is_file():
        try:
            got = decode(asset.read_bytes())
            check("asset defconf", got.get("Version") == "23.08"
                  and len(got.get("Servers", [])) == 20
                  and len(got.get("Tweaks", [])) == 900,
                  "Version=%s Servers=%d Tweaks=%d" % (
                      got.get("Version"), len(got.get("Servers", [])),
                      len(got.get("Tweaks", []))))
        except Exception as exc:  # noqa: BLE001
            check("asset defconf", False, repr(exc))
    else:
        print("SKIP asset defconf (no está junto al script)")

    # 3. Plaintext JSON passes through unchanged (p5/f.a behaviour).
    try:
        got = decode('{"Version": "x", "Servers": [], "Tweaks": []}')
        check("JSON en claro", got.get("Version") == "x")
    except Exception as exc:  # noqa: BLE001
        check("JSON en claro", False, repr(exc))

    # 4. Garbage is rejected, never half-decoded.
    try:
        decode("AAAA")
        check("basura rechazada", False, "no lanzó error")
    except DecodeError:
        check("basura rechazada", True)
    except Exception as exc:  # noqa: BLE001
        check("basura rechazada", False, repr(exc))

    print("self-test: %d/%d OK" % (4 - len(failures), 4) if asset.is_file()
          else "self-test: %d fallos" % len(failures))
    return 1 if failures else 0


# ------------------------------------------------------------- CLI
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Decodificador del catálogo de Edoztunnel Pro 2.4.")
    parser.add_argument("--url", nargs="?", const=CATALOG_URL, default=None,
                        help="Descargar el catálogo (por defecto, el URL del "
                             "catálogo gratuito; acepta un URL explícito).")
    parser.add_argument("--vip", action="store_true",
                        help="Descargar el catálogo VIP en vez del gratuito.")
    parser.add_argument("--file", type=Path,
                        help="Decodificar un catálogo guardado (Base64 Salted__).")
    parser.add_argument("--asset", action="store_true",
                        help="Decodificar el asset defconf incluido junto al script.")
    parser.add_argument("--self-test", action="store_true",
                        help="Pruebas offline (round-trip + asset defconf).")
    parser.add_argument("-o", "--output", type=Path,
                        help="Escribir el JSON decodificado en este archivo.")
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    try:
        if args.asset:
            asset = Path(__file__).with_name("defconf")
            if not asset.is_file():
                print("asset defconf no encontrado junto al script", file=sys.stderr)
                return 2
            data = asset.read_bytes()
            source = "asset defconf"
        elif args.file is not None:
            data = args.file.read_bytes()
            source = str(args.file)
        else:
            url = VIP_CATALOG_URL if args.vip else (args.url or CATALOG_URL)
            data = fetch_catalog(url)
            source = url
        doc = decode(data)
    except DecodeError as exc:
        if args.vip:
            print("VIP_DECRYPT_FAILED: el catálogo VIP en vivo no se pudo "
                  "descifrar con el método de la app (%s). No se inventan "
                  "servidores VIP." % exc, file=sys.stderr)
        else:
            print("ERROR [%s]: %s" % (exc.code, exc), file=sys.stderr)
        return 2
    except OSError as exc:
        print("ERROR: no se pudo leer la entrada: %s" % exc, file=sys.stderr)
        return 2

    out = json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if args.output is not None:
        args.output.write_text(out, encoding="utf-8")
    else:
        sys.stdout.write(out)
    print("Fuente: %s" % source, file=sys.stderr)
    print("Resumen: %s" % summary(doc), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
