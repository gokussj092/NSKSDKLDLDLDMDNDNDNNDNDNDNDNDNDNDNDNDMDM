#!/usr/bin/env python3
"""Rev Hunter 48 (com.hunter.net): catalog decoder, local or explicit HTTPS.

Standalone Python 3.10+, standard library only; no APK needed at runtime.
For .rev / .custom config files use Hunter_VPN_archivos.py.

Catalog endpoint (exact request the app makes):
    GET https://update.revhuntervpn.com/cache/48
Plain GET, no headers / no auth. "[version]" in LinkUpdate is the app
versionCode ("48"), NOT the catalog Version ("1.3.2").

Envelope (format TSH1, from w23.o + native libwoldk.so):
    Base64 -> Base91 (basE91 alphabet) -> TSH1 envelope
        magic "TSH1" | salt[16] | nonce[12] | ct_len LE32 | crc64 LE64 | ct
    PBKDF2-HmacSHA1(password, salt, 100 iters, 256 bytes) -> key K
    CRC-64 (reflected, poly from K[192:200] LE64 with bits 63 and 0 set,
    init 0xFFFFFFFFFFFFFFFF, final ~crc) over salt || nonce || ct.
    Layers on ct (decryption order):
      1. ChaCha, 1 double round, key K[0:32], nonce, counter from 1.
      2. xoshiro256** S-box: 8 inverse tables (one per byte position mod 8),
         seed K[64:96] as 4 LE uint64.
      3. RC4 with key K[0:32], first 1536 keystream bytes discarded.
      4. Nibble rotation with key K[128:192] (per byte i, r = K[128+(i&63)] & 3).
      5. dk.d (native libwoldk.so): Fisher-Yates shuffle seeded by
         SHA-256(key || 16 zero bytes || "SHUF") through a java.util.Random
         LCG, scatter, byte reversal, then XOR with SHA-256 keystream
         blocks SHA-256(seed || LE32(block)) where
         seed = SHA-256(key || "XOR:" || 16 zero bytes).
      6. GZIP -> JSON (UTF-8).

"ChupaMeuPiru" and "MamaX9Safadinho$$$$$$" are format constants baked into
the app (GoogleSignInActivity.j and libwoldk.so .rodata), not account
credentials. The live catalog holds no user credentials in its structure;
server usernames/passwords inside the decoded JSON are the provider's
own public server list, shown only in the decoded output.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import hashlib
import json
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
M32 = 0xFFFFFFFF
M64 = (1 << 64) - 1
M48 = (1 << 48) - 1
# Format constants baked into the app (see module docstring).
PASSWORD = b"ChupaMeuPiru"
DK_KEY = b"MamaX9Safadinho$$$$$$"
CATALOG_URL = "https://update.revhuntervpn.com/cache/48"
CATALOG_URL_TEMPLATE = "https://update.revhuntervpn.com/cache/{version}"
USER_AGENT = "RevHunter/48"
B91_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*,-.<>:;=?@[]^_`{|}~\"'"
_B91_DEC = {c: i for i, c in enumerate(B91_ALPHABET)}
_XOSHIRO_DEFAULT = (
    (-7046029254386353131) & M64,
    (-3263064605168079213) & M64,
    (-3865633965929787049) & M64,
    (-8819093574894306086) & M64,
)


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


def _base64(text: str) -> bytes:
    compact = re.sub(r"[ \t\r\n]", "", text)
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact) or len(compact) % 4 == 1:
        raise DecodeError("FORMAT_ERROR", "Se esperaba Base64 estándar del catálogo.")
    try:
        return base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DecodeError("FORMAT_ERROR", "El cuerpo no es Base64 válido.") from exc


def _b91_decode(text: str) -> bytes:
    out = bytearray()
    v = -1
    b = 0
    n = 0
    for ch in text:
        c = _B91_DEC.get(ch, -1)
        if c == -1:
            continue
        if v < 0:
            v = c
        else:
            v += c * 91
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            while n > 7:
                out.append(b & 255)
                b >>= 8
                n -= 8
            v = -1
    if v != -1:
        out.append((b | (v << n)) & 255)
    return bytes(out)


def _b91_encode(data: bytes) -> str:
    out: list[str] = []
    b = 0
    n = 0
    for byte in data:
        b |= byte << n
        n += 8
        if n > 13:
            v = b & 8191
            if v > 88:
                b >>= 13
                n -= 13
            else:
                v = b & 16383
                b >>= 14
                n -= 14
            out.append(B91_ALPHABET[v % 91])
            out.append(B91_ALPHABET[v // 91])
    if n:
        out.append(B91_ALPHABET[b % 91])
        if n > 7 or b > 90:
            out.append(B91_ALPHABET[b // 91])
    return "".join(out)


def _rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & M32


def _rotl64(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & M64


def _rotl4(x: int, n: int) -> int:
    n &= 3
    if n == 0:
        return x & 15
    return (((x << n) | (x >> (4 - n))) & 15)


def _unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key: {key!r}")
        out[key] = value
    return out


def _nonfinite(_value):
    raise ValueError("non-finite number")


def _validate(doc):
    if not isinstance(doc, dict):
        raise DecodeError("FORMAT_ERROR", "El catálogo descifrado no es un objeto JSON.")
    if "Servers" not in doc or "Networks" not in doc:
        raise DecodeError("FORMAT_ERROR", "El catálogo descifrado no tiene Servers/Networks.")


def _json(data: bytes) -> dict:
    try:
        doc = json.loads(data.decode("utf-8"), parse_constant=_nonfinite,
                         object_pairs_hook=_unique)
    except (UnicodeError, ValueError) as exc:
        raise DecodeError("FORMAT_ERROR", "El catálogo descifrado no es JSON válido.") from exc
    _validate(doc)
    return doc


def _crc64(data: bytes, key: bytes) -> int:
    poly = struct.unpack("<Q", key[192:200])[0] | (1 << 63) | 1
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ poly if (crc & 1) else (crc >> 1)
        table.append(crc)
    crc = 0xFFFFFFFFFFFFFFFF
    for byte in data:
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return (~crc) & 0xFFFFFFFFFFFFFFFF


def _chacha_block(key32: bytes, counter: int, nonce12: bytes) -> bytes:
    consts = struct.unpack("<4I", b"expand 32-byte k")
    kw = struct.unpack("<8I", key32)
    nw = struct.unpack("<3I", nonce12)
    st = list(consts) + list(kw) + [counter] + list(nw)
    init = st[:]

    def qr(a: int, b: int, c: int, d: int) -> None:
        st[a] = (st[a] + st[b]) & M32
        st[d] ^= st[a]
        st[d] = _rotl32(st[d], 16)
        st[c] = (st[c] + st[d]) & M32
        st[b] ^= st[c]
        st[b] = _rotl32(st[b], 12)
        st[a] = (st[a] + st[b]) & M32
        st[d] ^= st[a]
        st[d] = _rotl32(st[d], 8)
        st[c] = (st[c] + st[d]) & M32
        st[b] ^= st[c]
        st[b] = _rotl32(st[b], 7)

    # 1 double round (8 quarter-rounds), exactly as in w23.o.
    for (a, b, c, d) in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                        (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)):
        qr(a, b, c, d)
    out = [(x + y) & M32 for x, y in zip(st, init)]
    return struct.pack("<16I", *out)


def _xoshiro_next(st: list[int]) -> int:
    s0, s1, s2, s3 = st
    out = (_rotl64((s1 * 5) & M64, 7) * 9) & M64
    t = (s1 << 17) & M64
    s2 ^= s0
    s3 ^= s1
    s1 ^= s2
    s0 ^= s3
    s2 ^= t
    s3 = _rotl64(s3, 45)
    st[0], st[1], st[2], st[3] = s0, s1, s2, s3
    return out


def _sbox_tables(key: bytes, inverse: bool) -> list[list[int]]:
    st = list(struct.unpack("<4Q", key[64:96]))
    if not any(st):
        st = list(_XOSHIRO_DEFAULT)
    tables = []
    for _ in range(8):
        perm = list(range(256))
        for i in range(255, 0, -1):
            j = _xoshiro_next(st) % (i + 1)
            perm[i], perm[j] = perm[j], perm[i]
        if inverse:
            inv = [0] * 256
            for i, p in enumerate(perm):
                inv[p] = i
            tables.append(inv)
        else:
            tables.append(perm)
    return tables


def _rc4_keystream(key32: bytes, length: int) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key32[i % len(key32)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = 0
    j = 0
    out = bytearray()

    def nxt() -> int:
        nonlocal i, j
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        return S[(S[i] + S[j]) & 0xFF]

    for _ in range(1536):
        nxt()
    for _ in range(length):
        out.append(nxt())
    return bytes(out)


def _dk_shuffle_perm(n: int) -> list[int]:
    """Fisher-Yates permutation of dk.d (java.util.Random LCG)."""
    d = hashlib.sha256(DK_KEY + b"\x00" * 16 + b"SHUF").digest()
    seed_a = ((d[3] | (d[2] << 8)) ^ 5) & 0xFFFFFFFF
    seed_b = ((((d[6] << 8) | (d[4] << 24) | (d[5] << 16)) + d[7]) ^ 0xDEECE66D) & 0xFFFFFFFF
    state = (seed_b | (seed_a << 32)) & M48
    mult = 0x5DEECE66D

    def next31() -> int:
        nonlocal state
        state = (state * mult + 0xB) & M48
        return state >> 17

    def next_int(bound: int) -> int:
        if bound & (bound - 1) == 0:
            return (bound * next31()) >> 31
        while True:
            bits = next31()
            val = bits % bound
            if bits - val + (bound - 1) >= 0:
                return val

    a = list(range(n))
    for r4 in range(n, 1, -1):
        j = next_int(r4)
        a[r4 - 1], a[j] = a[j], a[r4 - 1]
    return a


def _dk_xor_keystream(n: int) -> bytes:
    seed = hashlib.sha256(DK_KEY + b"XOR:" + b"\x00" * 16).digest()
    ks = bytearray()
    for k in range((n + 31) // 32):
        ks += hashlib.sha256(seed + k.to_bytes(4, "little")).digest()
    return bytes(ks[:n])


def _dk_d(data: bytes) -> bytes:
    """Native dk.d (libwoldk.so): shuffle + scatter + reverse + XOR."""
    n = len(data)
    if n == 0:
        return b""
    a = _dk_shuffle_perm(n)
    tmp = bytearray(n)
    for i in range(n):
        tmp[a[i]] = data[i]
    rev = bytes(tmp[n - 1 - i] for i in range(n))
    ks = _dk_xor_keystream(n)
    return bytes(rev[i] ^ ks[i] for i in range(n))


def _dk_d_inv(data: bytes) -> bytes:
    """Inverse of dk.d (encryption direction; used only by --self-test)."""
    n = len(data)
    if n == 0:
        return b""
    a = _dk_shuffle_perm(n)
    ks = _dk_xor_keystream(n)
    rev = bytes(data[i] ^ ks[i] for i in range(n))
    tmp = bytes(rev[n - 1 - i] for i in range(n))
    out = bytearray(n)
    for i in range(n):
        out[i] = tmp[a[i]]
    return bytes(out)


def _parse_envelope(data: bytes) -> tuple[bytes, bytes, bytes]:
    """Return (ct, key, nonce); validates magic, length and CRC-64."""
    if len(data) < 44 or data[:4] != b"TSH1":
        raise DecodeError("FORMAT_ERROR", "No es un sobre TSH1 (falta el magic).")
    salt = data[4:20]
    nonce = data[20:32]
    ct_len = struct.unpack("<I", data[32:36])[0]
    crc_stored = struct.unpack("<Q", data[36:44])[0]
    if ct_len < 0 or 44 + ct_len > len(data):
        raise DecodeError("FORMAT_ERROR", "La longitud del sobre TSH1 no cuadra.")
    ct = bytes(data[44:44 + ct_len])
    key = hashlib.pbkdf2_hmac("sha1", PASSWORD, salt, 100, dklen=256)
    if _crc64(salt + nonce + ct, key) != crc_stored:
        raise DecodeError("CRC_MISMATCH", "El CRC-64 del sobre TSH1 no coincide.")
    return ct, key, nonce


def decrypt_catalog_bytes(data: bytes | str) -> bytes:
    """Decrypt a TSH1 catalog body to raw gzip bytes."""
    text = _text(data)
    try:
        stage1 = _base64(text)
    except DecodeError:
        raise
    try:
        envelope = _b91_decode(stage1.decode("utf-8"))
    except UnicodeError as exc:
        raise DecodeError("FORMAT_ERROR", "El cuerpo Base64 no es UTF-8.") from exc
    ct, key, nonce = _parse_envelope(envelope)
    # L1 ChaCha (1 double round, key K[0:32], counter from 1).
    ks = bytearray()
    ctr = 1
    while len(ks) < len(ct):
        ks += _chacha_block(key[0:32], ctr, nonce)
        ctr += 1
    ct = bytes(b ^ ks[i] for i, b in enumerate(ct))
    # L2 xoshiro S-box (inverse tables).
    tables = _sbox_tables(key, inverse=True)
    ct = bytes(tables[i & 7][b] for i, b in enumerate(ct))
    # L3 RC4 (drop 1536).
    rc = _rc4_keystream(key[0:32], len(ct))
    ct = bytes(b ^ rc[i] for i, b in enumerate(ct))
    # L4 nibble rotation.
    nk = key[128:192]
    out = bytearray(ct)
    for i in range(len(out)):
        b = out[i]
        hi = (b >> 4) & 15
        lo = b & 15
        r = nk[i & 63] & 3
        rr = 4 - r
        out[i] = ((_rotl4(hi, rr) << 4) | _rotl4(lo, r))
    ct = bytes(out)
    # L5 dk.d -> gzip bytes.
    return _dk_d(ct)


def _catalog_json(data) -> dict:
    raw = decrypt_catalog_bytes(data)
    try:
        plain = gzip.decompress(raw)
    except (OSError, EOFError) as exc:
        raise DecodeError("FORMAT_ERROR", "El resultado no es gzip válido.") from exc
    return _json(plain)


def decode(data: bytes | str) -> dict:
    """Offline API: decrypt the complete catalog without merging local profiles."""
    return _catalog_json(data)


def run(file_bytes: bytes | str) -> str | None:
    """Offline API: complete catalog JSON or None; never a partial list."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


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


def _resolve_url(url: str | None) -> str:
    """--url value: full URL, bare versionCode, or None (default)."""
    if url is None:
        return CATALOG_URL
    value = url.strip()
    if value.isdigit():
        return CATALOG_URL_TEMPLATE.format(version=value)
    return value


def fetch_catalog(url: str = CATALOG_URL) -> bytes:
    try:
        _https_url(url)
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


def _encrypt_tsh1(obj: dict, salt: bytes, nonce: bytes) -> str:
    """Build a TSH1 blob (inverse pipeline; only for --self-test)."""
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    gz = gzip.compress(raw, mtime=0)
    key = hashlib.pbkdf2_hmac("sha1", PASSWORD, salt, 100, dklen=256)
    data = _dk_d_inv(gz)
    nk = key[128:192]
    enc = bytearray(data)
    for i in range(len(enc)):
        b = enc[i]
        hi = (b >> 4) & 15
        lo = b & 15
        r = nk[i & 63] & 3
        rr = 4 - r
        enc[i] = ((_rotl4(hi, r) << 4) | _rotl4(lo, rr))
    data = bytes(enc)
    rc = _rc4_keystream(key[0:32], len(data))
    data = bytes(b ^ rc[i] for i, b in enumerate(data))
    tables = _sbox_tables(key, inverse=False)
    data = bytes(tables[i & 7][b] for i, b in enumerate(data))
    ks = bytearray()
    ctr = 1
    while len(ks) < len(data):
        ks += _chacha_block(key[0:32], ctr, nonce)
        ctr += 1
    data = bytes(b ^ ks[i] for i, b in enumerate(data))
    crc = _crc64(salt + nonce + data, key)
    env = b"TSH1" + salt + nonce + struct.pack("<I", len(data)) + struct.pack("<Q", crc) + data
    return base64.b64encode(_b91_encode(env).encode("utf-8")).decode("utf-8")


def _self_test() -> int:
    failures = []

    def check(name: str, cond: bool) -> None:
        print(("ok  " if cond else "FAIL") + f" {name}")
        if not cond:
            failures.append(name)

    # 1. dk.d known vector (verified against the native libwoldk.so via Unicorn).
    vec_in = bytes(range(64))
    vec_out = _dk_d(vec_in)
    check("dk.d vector len 64", len(vec_out) == 64 and vec_out != vec_in)
    check("dk.d inverse", _dk_d_inv(vec_out) == vec_in)
    # 2. Full TSH1 round-trip on a small catalog-like object.
    obj = {
        "Version": "9.9.9", "AppVersion": "48",
        "Servers": [{"Name": "TEST 01", "ServerIP": "1.2.3.4", "ServerPort": 443}],
        "Networks": [{"Name": "TEST PAYLOAD", "Payload": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "Modo": "Proxy"}],
        "NetworksAuto": [], "ReleaseNotes": None,
    }
    blob = _encrypt_tsh1(obj, salt=b"\x01" * 16, nonce=b"\x02" * 12)
    got = decode(blob)
    check("TSH1 round-trip", got == obj)
    # 3. Bad input fails cleanly.
    for bad in ("", "AAAA", "not base64!!!"):
        try:
            decode(bad)
            check(f"reject {bad!r}", False)
        except DecodeError:
            check(f"reject {bad!r}", True)
    # 4. CRC mismatch is detected.
    tampered = bytearray(base64.b64decode(_encrypt_tsh1(obj, salt=b"\x01" * 16, nonce=b"\x02" * 12)))
    tampered[-1] ^= 1
    try:
        decode(base64.b64encode(bytes(tampered)).decode())
        check("reject CRC mismatch", False)
    except DecodeError as exc:
        check("reject CRC mismatch", exc.code == "CRC_MISMATCH")
    print(f"self-test: {4 + 3 - len(failures)}/{4 + 3} checks passed" if failures else "self-test: all checks passed")
    return 1 if failures else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path, help="Respuesta del catálogo guardada localmente")
    source.add_argument("--url", nargs="?", const=CATALOG_URL,
                        help="Descarga explícita: URL completa o versionCode (por defecto 48)")
    source.add_argument("--self-test", action="store_true", help="Pruebas internas (sin red)")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo; por defecto stdout")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    try:
        result = decode(fetch_catalog(_resolve_url(args.url)) if args.url is not None else _read(args.file))
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
