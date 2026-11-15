#!/usr/bin/env python3
"""Fat Tunnel Lite (vpn.jx.strongudp, versionCode 12, versionName Fat V1.12):
catalog decoder, local or explicit HTTPS.

Standalone Python 3.10+, standard library only; no APK needed at runtime.
For .fat files use Fat_Tunnel_Lite_archivos.py.
Fat Tunnel Lite has no custom text/link scheme of its own (see README.md):
it only handles the standard v2rayNG links v2rayng://install-config and
v2rayng://install-sub, which SP-DECODE already decodes as vmess/vless/
trojan/ss links and subscriptions.

Method verified against THIS APK (jadx 1.5.3; libgojni.so, a Go 1.24.3
binary of github.com/2dust/AndroidLibXrayLite, disassembled with Capstone;
no LSParanoid/Deobfuscator class exists in this DEX):
  * Download: Hometab$configUpdate$1 calls Libv2ray.cu(currentVersion).
    AndroidLibXrayLite.CU (0x1016880) builds
    http.NewRequestWithContext(ctx, "GET", "https://strongteam.co/api/fattunnel/",
    nil), sets exactly one header, User-Agent: Fat Tunnel Lite, and calls
    http.Client.Do. The response body is passed to AndroidLibXrayLite.decrypt
    (0x1013cc0), then parsed as JSON and compared with compareVersion.
    Libv2ray.gfc() returns the same fresh config; HomeFragment stores it
    under the "KidConfig7" preference. The bundled asset assets/configfile.json
    is decrypted by AndroidLibXrayLite.DO (0x1014610), reached from Java as
    Libv2ray.do_ via Hometab.Companion.a.
  * Cipher (both functions, same layout): Base64 -> blob
    salt[0:16] || nonce[16:28] || ciphertext[28:-16] || tag[-16:]
    -> AES-256-GCM with AAD = salt. The key is Argon2id
    (time=3, memory=8192 KiB, parallelism=1, keyLen=32, version 0x13)
    over the format password with salt = blob[0:16].
  * Two format passwords (shared constants of the app, not account
    credentials): the remote catalog and .fat files use the current one
    (decrypt/Encrypt/parseConfig); the bundled asset and older .fat files
    use the legacy one (DO). decode() tries the current one first and
    falls back to the legacy one, mirroring ConfigFileParser
    (parseConfig, then DO).
  * The server (Cloudflare) requires the User-Agent: without it the
    endpoint answers 404; with it, 200 and the full body in a single GET.
    It ignores Range (answers 200 with the full body), so this script
    does not resume by ranges. The response is chunked with no
    Content-Length; through the egress proxy used here, sending
    'Connection: close' (which urllib.request adds by default) tears the
    connection down before the chunked body finishes (0/7 complete
    downloads, partials of 64-214 KiB), while 'Connection: keep-alive'
    or no Connection header delivers the full body every time (3/3).
    fetch_catalog therefore uses http.client directly and never sends
    'Connection: close'; a truncated read is retried with a fresh GET
    (up to 6 attempts), and the GCM tag in decode() is what proves a
    body is complete.
  * Pure-Python Argon2id (RFC 9106) and AES-256-GCM are implemented here
    in the standard library only (hashlib.blake2b + the BlaMka round);
    they were verified against argon2-cffi / cryptography, the RFC 9106
    Argon2id test vector, a NIST AES-GCM vector, the bundled asset and a
    live download. A decode takes ~15-20 s on this machine (Argon2id
    dominates); that is the cost of the format, not of the network.

Live test 2026-11-13 (this script, --url, single GET with the exact
User-Agent): HTTP 200, remote Version 2.881, 16 servers, 217 payloads
(Networks). Bundled asset: Version 1.01, 1 server, 156 payloads.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from http.client import HTTPException, HTTPSConnection, IncompleteRead
import hashlib
import json
import math
import os
from pathlib import Path
import re
import struct
import sys
from urllib.parse import urlsplit
import zipfile

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1
# Format constants of the app (see module docstring), not account credentials.
CATALOG_PASSWORD = b"FatTUNNELP@AssWodII"  # current: decrypt/Encrypt/parseConfig
BUNDLED_PASSWORD = b"FatTUNNELP@AssWod"    # legacy: DO / bundled asset
CATALOG_URL = "https://strongteam.co/api/fattunnel/"
USER_AGENT = "Fat Tunnel Lite"  # Required: without it the endpoint answers 404.
LIST_FIELDS = ("Servers", "Networks")
BUNDLED_ASSET = "assets/configfile.json"


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
    except (ValueError, binascii.Error) as exc:
        raise DecodeError("FORMAT_ERROR", "Base64 inválido.") from exc


def _unique(pairs):
    result = {}
    for key in pairs:
        if key[0] in result:
            raise ValueError("duplicate key")
        result[key[0]] = key[1]
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


# ------------------------------------------------------- Argon2id (RFC 9106)
def _rotr64(x, n):
    return ((x >> n) | (x << (64 - n))) & MASK64


def _blamka_g1(a, b, c, d):
    a = (a + b + 2 * (a & MASK32) * (b & MASK32)) & MASK64
    d = _rotr64(d ^ a, 32)
    c = (c + d + 2 * (c & MASK32) * (d & MASK32)) & MASK64
    b = _rotr64(b ^ c, 24)
    return a, b, c, d


def _blamka_g2(a, b, c, d):
    a = (a + b + 2 * (a & MASK32) * (b & MASK32)) & MASK64
    d = _rotr64(d ^ a, 16)
    c = (c + d + 2 * (c & MASK32) * (d & MASK32)) & MASK64
    b = _rotr64(b ^ c, 63)
    return a, b, c, d


def _blake2_round(v):
    """One BlaMka round on a 16-word list (mutated in place)."""
    v[0], v[4], v[8], v[12] = _blamka_g1(v[0], v[4], v[8], v[12])
    v[0], v[4], v[8], v[12] = _blamka_g2(v[0], v[4], v[8], v[12])
    v[1], v[5], v[9], v[13] = _blamka_g1(v[1], v[5], v[9], v[13])
    v[1], v[5], v[9], v[13] = _blamka_g2(v[1], v[5], v[9], v[13])
    v[2], v[6], v[10], v[14] = _blamka_g1(v[2], v[6], v[10], v[14])
    v[2], v[6], v[10], v[14] = _blamka_g2(v[2], v[6], v[10], v[14])
    v[3], v[7], v[11], v[15] = _blamka_g1(v[3], v[7], v[11], v[15])
    v[3], v[7], v[11], v[15] = _blamka_g2(v[3], v[7], v[11], v[15])
    v[0], v[5], v[10], v[15] = _blamka_g1(v[0], v[5], v[10], v[15])
    v[0], v[5], v[10], v[15] = _blamka_g2(v[0], v[5], v[10], v[15])
    v[1], v[6], v[11], v[12] = _blamka_g1(v[1], v[6], v[11], v[12])
    v[1], v[6], v[11], v[12] = _blamka_g2(v[1], v[6], v[11], v[12])
    v[2], v[7], v[8], v[13] = _blamka_g1(v[2], v[7], v[8], v[13])
    v[2], v[7], v[8], v[13] = _blamka_g2(v[2], v[7], v[8], v[13])
    v[3], v[4], v[9], v[14] = _blamka_g1(v[3], v[4], v[9], v[14])
    v[3], v[4], v[9], v[14] = _blamka_g2(v[3], v[4], v[9], v[14])


def _compress_block(prev, ref):
    """G(prev, ref): 1024-byte blocks as lists of 128 uint64 (little-endian).

    R = prev XOR ref; Z = R; apply the BlaMka round first to the 8 groups
    of 16 consecutive words, then to the 8 interleaved pairs strided by 16
    (2i, 2i+1, 16+2i, 17+2i, ..., 112+2i, 113+2i); return R XOR Z.
    """
    r = [p ^ q for p, q in zip(prev, ref)]
    z = list(r)
    for i in range(8):
        w = z[16 * i:16 * i + 16]
        _blake2_round(w)
        z[16 * i:16 * i + 16] = w
    for i in range(8):
        idx = [2 * i + 16 * k + b for k in range(8) for b in (0, 1)]
        w = [z[j] for j in idx]
        _blake2_round(w)
        for j, val in zip(idx, w):
            z[j] = val
    return [a ^ b for a, b in zip(r, z)]


def _blake2b_long(outlen, data):
    """H' variable-length Blake2b (RFC 9106 3.2.2): the output length is
    PREPENDED (LE32) to the input."""
    if outlen <= 64:
        return hashlib.blake2b(struct.pack("<I", outlen) + data,
                               digest_size=outlen).digest()
    r = (outlen + 31) // 32 - 2
    v = hashlib.blake2b(struct.pack("<I", outlen) + data,
                        digest_size=64).digest()
    out = bytearray(v[:32])
    for _ in range(2, r + 1):
        v = hashlib.blake2b(v, digest_size=64).digest()
        out += v[:32]
    out += hashlib.blake2b(v, digest_size=outlen - 32 * r).digest()
    return bytes(out)


def _argon2id(password, salt, time_cost, memory_kib, parallelism, tag_len,
              secret=b"", ad=b"", version=0x13):
    """Argon2id key derivation (RFC 9106). Returns tag_len bytes."""
    p, t, m = parallelism, time_cost, memory_kib
    h0 = hashlib.blake2b(
        struct.pack("<I", p) + struct.pack("<I", tag_len)
        + struct.pack("<I", m) + struct.pack("<I", t)
        + struct.pack("<I", version) + struct.pack("<I", 2)  # y = 2 (id)
        + struct.pack("<I", len(password)) + password
        + struct.pack("<I", len(salt)) + salt
        + struct.pack("<I", len(secret)) + secret
        + struct.pack("<I", len(ad)) + ad,
        digest_size=64).digest()
    m_prime = 4 * p * (m // (4 * p))
    q = m_prime // p  # blocks per lane
    seg_len = q // 4
    mem = []
    for lane in range(p):
        lane_mem = []
        for blk in (0, 1):
            raw = _blake2b_long(1024, h0 + struct.pack("<I", blk) + struct.pack("<I", lane))
            lane_mem.append(list(struct.unpack("<128Q", raw)))
        lane_mem += [None] * (q - 2)
        mem.append(lane_mem)
    zero = [0] * 128
    for pass_n in range(t):
        for slice_n in range(4):
            data_independent = (pass_n == 0 and slice_n < 2)
            addr_block = [0] * 128
            input_block = [0] * 128
            if data_independent:
                input_block[0] = pass_n
                input_block[2] = slice_n
                input_block[3] = m_prime
                input_block[4] = t
                input_block[5] = 2  # y = id
            start = 0 if (pass_n != 0 or slice_n != 0) else 2
            for lane in range(p):
                if data_independent:
                    input_block[1] = lane
                    input_block[6] = 0
                    addr_block = None
                for index in range(start, seg_len):
                    abs_index = slice_n * seg_len + index
                    prev_index = (abs_index - 1) % q
                    prev = mem[lane][prev_index]
                    if data_independent:
                        if addr_block is None or index % 128 == 0:
                            input_block[6] += 1
                            ib = list(struct.unpack("<128Q", struct.pack("<128Q", *input_block)))
                            tmp = _compress_block(zero, ib)
                            addr_block = _compress_block(zero, tmp)
                        j = addr_block[index % 128]
                        j1 = j & MASK32
                        j2 = (j >> 32) & MASK32
                    else:
                        j1 = prev[0] & MASK32
                        j2 = (prev[0] >> 32) & MASK32
                    ref_lane = j2 % p
                    if pass_n == 0 and slice_n == 0:
                        ref_lane = lane  # first slice: same lane only
                    same_lane = (ref_lane == lane)
                    if pass_n == 0:
                        if slice_n == 0:
                            ref_area = index - 1
                        elif same_lane:
                            ref_area = slice_n * seg_len + index - 1
                        else:
                            ref_area = slice_n * seg_len + (-1 if index == 0 else 0)
                    elif same_lane:
                        ref_area = q - seg_len + index - 1
                    else:
                        ref_area = q - seg_len + (-1 if index == 0 else 0)
                    rel = j1
                    rel = (rel * rel) >> 32
                    rel = ref_area - 1 - ((ref_area * rel) >> 32)
                    start_pos = 0 if pass_n == 0 else ((slice_n + 1) * seg_len) % q
                    ref_index = (start_pos + rel) % q
                    ref = mem[ref_lane][ref_index]
                    cur = _compress_block(prev, ref)
                    if pass_n != 0:
                        cur = [a ^ b for a, b in zip(cur, mem[lane][abs_index])]
                    mem[lane][abs_index] = cur
    final = mem[0][q - 1][:]
    for lane in range(1, p):
        final = [a ^ b for a, b in zip(final, mem[lane][q - 1])]
    return _blake2b_long(tag_len, struct.pack("<128Q", *final))


# ------------------------------------------------------------- AES-256-GCM
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
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
_GCM_R = 0xe1000000000000000000000000000000


def _aes_key_expand(key):
    w = [x for grp in (struct.unpack(">4I", key[i:i + 16]) for i in range(0, 32, 16)) for x in grp]
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


def _aes_encrypt_block(key_words, block):
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

        def xtime(x):
            return ((x << 1) ^ (0x1b if x & 0x80 else 0)) & 0xff
        out = [0] * 4
        for c in range(4):
            a0, a1, a2, a3 = sb[4 * c], sb[4 * c + 1], sb[4 * c + 2], sb[4 * c + 3]
            out[c] = (xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3) << 24 \
                | (a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3) << 16 \
                | (a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3)) << 8 \
                | ((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3))
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


def _gf_mul(x, y):
    z = 0
    v = y
    for _ in range(128):
        if (x >> 127) & 1:
            z ^= v
        v = (v >> 1) ^ _GCM_R if v & 1 else v >> 1
        x = (x << 1) & ((1 << 128) - 1)
    return z


def _ghash(h, data):
    y = 0
    for i in range(0, len(data), 16):
        y = _gf_mul(y ^ int.from_bytes(data[i:i + 16], "big"), h)
    return y


def _aes_gcm_decrypt(key, nonce, ciphertext, tag, aad=b""):
    """AES-256-GCM decrypt (pure stdlib). nonce: 12 bytes."""
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    kw = _aes_key_expand(key)
    h = int.from_bytes(_aes_encrypt_block(kw, b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    pt = bytearray()
    counter = 1
    for i in range(0, len(ciphertext), 16):
        chunk = ciphertext[i:i + 16]
        ctr = nonce + struct.pack(">I", counter + 1)
        ks = _aes_encrypt_block(kw, ctr)
        pt += bytes(a ^ b for a, b in zip(chunk, ks))
        counter += 1

    def pad16(d):
        return d + b"\x00" * ((-len(d)) % 16)
    s = _ghash(h, pad16(aad) + pad16(ciphertext)
               + struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8))
    ej0 = _aes_encrypt_block(kw, j0)
    calc_tag = (s ^ int.from_bytes(ej0, "big")).to_bytes(16, "big")
    if calc_tag != tag:
        raise ValueError("GCM tag mismatch")
    return bytes(pt)


def _aes_gcm_encrypt(key, nonce, plaintext, aad=b""):
    """AES-256-GCM encrypt (pure stdlib). Returns (ciphertext, tag)."""
    kw = _aes_key_expand(key)
    h = int.from_bytes(_aes_encrypt_block(kw, b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    ct = bytearray()
    counter = 1
    for i in range(0, len(plaintext), 16):
        chunk = plaintext[i:i + 16]
        ctr = nonce + struct.pack(">I", counter + 1)
        ks = _aes_encrypt_block(kw, ctr)
        ct += bytes(a ^ b for a, b in zip(chunk, ks))
        counter += 1

    def pad16(d):
        return d + b"\x00" * ((-len(d)) % 16)
    s = _ghash(h, pad16(aad) + pad16(bytes(ct))
               + struct.pack(">QQ", len(aad) * 8, len(ct) * 8))
    ej0 = _aes_encrypt_block(kw, j0)
    tag = (s ^ int.from_bytes(ej0, "big")).to_bytes(16, "big")
    return bytes(ct), tag


def _encrypt_blob(plaintext: bytes, password: bytes, salt: bytes, nonce: bytes) -> str:
    """Inverse of decrypt_catalog_bytes (mirrors AndroidLibXrayLite.Encrypt)."""
    key = _argon2id(password, salt, time_cost=3, memory_kib=8192,
                    parallelism=1, tag_len=32)
    ciphertext, tag = _aes_gcm_encrypt(key, nonce, plaintext, aad=salt)
    return base64.b64encode(salt + nonce + ciphertext + tag).decode("ascii")


# ------------------------------------------------------------------ catalog
def decrypt_catalog_bytes(data: bytes | str, *, password: bytes | None = None) -> bytes:
    """Base64 -> Argon2id -> AES-256-GCM -> JSON bytes (see module docstring)."""
    if password is None:
        password = CATALOG_PASSWORD
    blob = _base64(_text(data))
    if len(blob) < 16 + 12 + 16:
        raise DecodeError("TRUNCATED", "El catálogo es demasiado corto para el formato.")
    salt, nonce, rest = blob[:16], blob[16:28], blob[28:]
    ciphertext, tag = rest[:-16], rest[-16:]
    key = _argon2id(password, salt, time_cost=3, memory_kib=8192,
                    parallelism=1, tag_len=32)
    try:
        return _aes_gcm_decrypt(key, nonce, ciphertext, tag, aad=salt)
    except ValueError as exc:
        raise DecodeError("DECRYPT_FAILED", "La autenticación GCM falló.") from exc


def _catalog_json(data) -> dict:
    doc = _json(data)
    if not any(field in doc for field in LIST_FIELDS):
        raise DecodeError("WRONG_DOCUMENT", "No hay listas de servidores o payloads en el catálogo.")
    for field in LIST_FIELDS:
        if field in doc and (not isinstance(doc[field], list) or any(not isinstance(v, dict) for v in doc[field])):
            raise DecodeError("WRONG_DOCUMENT", "Las listas de catálogo deben contener objetos completos.")
    return doc


def decode(data: bytes | str, *, passwords=(CATALOG_PASSWORD, BUNDLED_PASSWORD)) -> dict:
    """Offline API: decrypt the complete catalog (passwords in order)."""
    last = None
    for password in passwords:
        try:
            return _catalog_json(decrypt_catalog_bytes(data, password=password))
        except DecodeError as exc:
            if exc.code != "DECRYPT_FAILED":
                raise
            last = exc
    raise last


def run(file_bytes: bytes | str) -> str | None:
    """Offline API: complete catalog JSON or None; never a partial list."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


def summary(doc: dict) -> dict:
    """Counts only; never reproduces decrypted values."""
    out = {"Version": doc.get("Version")}
    for field in LIST_FIELDS:
        value = doc.get(field)
        out[field] = len(value) if isinstance(value, list) else None
    out["sections"] = sorted(doc.keys())
    return out


def _https_url(url: str):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment):
        raise ValueError("invalid HTTPS URL")
    return parsed


def _proxy_env():
    """(host, port, auth_header) from https_proxy/HTTPS_PROXY, or None.

    The proxy credentials rotate; they are read from the environment at
    call time, never stored.
    """
    raw = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY") or ""
    match = re.match(r"^https?://(?:([^:@]+):([^@]*)@)?([^:/]+):(\d+)", raw)
    if not match:
        return None
    user, password, host, port = match.groups()
    auth = None
    if user is not None:
        auth = "Basic " + base64.b64encode(
            f"{user}:{password or ''}".encode("utf-8")).decode("ascii")
    return host, int(port), auth


def _one_get(url, parsed):
    """One GET with http.client (never urllib: urllib adds
    'Connection: close', which truncates this chunked endpoint through
    the egress proxy used here -- the connection is torn down before the
    chunked body finishes. Without that header the full body arrives).
    Returns the complete body bytes."""
    proxy = _proxy_env()
    if proxy is not None:
        phost, pport, pauth = proxy
        conn = HTTPSConnection(phost, pport, timeout=60)
        tunnel_headers = {"Proxy-Authorization": pauth} if pauth else {}
        conn.set_tunnel(parsed.hostname, parsed.port or 443, tunnel_headers)
    else:
        conn = HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=60)
    try:
        conn.putrequest("GET", parsed.path or "/")
        conn.putheader("User-Agent", USER_AGENT)
        conn.putheader("Accept-Encoding", "identity")
        conn.putheader("Connection", "keep-alive")
        conn.endheaders()
        resp = conn.getresponse()
        if resp.status in (301, 302, 303, 307, 308):
            location = resp.getheader("Location")
            resp.read()
            if not location:
                raise DecodeError("DOWNLOAD_FAILED", "Redirección sin destino.")
            return _redirect(location)
        if resp.status != 200:
            resp.read()
            raise DecodeError("DOWNLOAD_FAILED", "El endpoint no devolvió 200.")
        try:
            data = resp.read()
        except IncompleteRead as exc:
            raise _Truncated(exc.partial or b"") from exc
        if len(data) > MAX_BYTES:
            raise DecodeError("SIZE_LIMIT", "La respuesta supera el límite de tamaño.")
        return data
    except (DecodeError, _Redirect, _Truncated):
        raise
    except (HTTPException, OSError, ValueError) as exc:
        raise DecodeError("DOWNLOAD_FAILED", "No se pudo descargar el catálogo mediante HTTPS.") from exc
    finally:
        conn.close()


def _redirect(location):
    raise _Redirect(location)


class _Redirect(Exception):
    def __init__(self, location):
        super().__init__("redirect")
        self.location = location


class _Truncated(Exception):
    def __init__(self, partial: bytes):
        super().__init__("download truncated")
        self.partial = partial


def fetch_catalog(url: str = CATALOG_URL) -> bytes:
    """Plain GET exactly as the app makes it (User-Agent required).

    The server answers the full body in one response and ignores Range,
    so there is no resume step. A truncated read is retried with a fresh
    GET (up to 3 attempts); the GCM tag in decode() is what proves a
    body is complete.
    """
    current = url
    for _redirect in range(6):
        _https_url(current)
        try:
            return _one_get(current, _https_url(current))
        except _Redirect as exc:
            current = exc.location
            continue
        except _Truncated:
            continue
    raise DecodeError("DOWNLOAD_TRUNCATED", "La descarga se cortó y no se pudo completar.")


def read_bundled(apk_path: Path) -> bytes:
    """assets/configfile.json from the APK (legacy password; see decode())."""
    try:
        with zipfile.ZipFile(apk_path) as zf:
            return zf.read(BUNDLED_ASSET)
    except (OSError, KeyError, zipfile.BadZipFile) as exc:
        raise DecodeError("APK_ERROR", "No se pudo leer el catálogo incrustado del APK.") from exc


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


def _self_test() -> int:
    """Synthetic round-trip self-test; uses no real files or network.

    Takes ~60-90 s (several pure-Python Argon2id runs). Cases:
    1. RFC 9106 Argon2id test vector. 2. NIST AES-256-GCM vector.
    3. Round-trip catalog with the current password.
    4. Round-trip catalog with the legacy password.
    5. Tampered GCM tag is rejected (DECRYPT_FAILED).
    """
    cases = []

    def check(name, ok):
        cases.append(ok)
        print(f"  [{'OK' if ok else 'FAIL'}] {name}")

    print("Fat_Tunnel_Lite self-test:")
    tag = _argon2id(bytes([0x01] * 32), bytes([0x02] * 16), 3, 32, 4, 32,
                    secret=bytes([0x03] * 8), ad=bytes([0x04] * 12))
    check("RFC 9106 Argon2id vector",
          tag.hex() == "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
    try:
        pt = _aes_gcm_decrypt(bytes(32), bytes(12),
                              bytes.fromhex("cea7403d4d606b6e074ec5d3baf39d18"),
                              bytes.fromhex("d0d1c8a799996bf0265b98b5d48ab919"))
        check("NIST AES-256-GCM vector", pt == bytes(16))
    except ValueError:
        check("NIST AES-256-GCM vector", False)
    salt = bytes(range(16))
    nonce = bytes(range(16, 28))
    doc = {"Version": "9.99", "ReleaseNotes": "self-test",
           "Servers": [{"Name": "Test", "ServerIPHost": "127.0.0.1"}],
           "Networks": [{"Name": "Test", "TunnelType": "V2Ray", "Payload": "x"}]}
    raw = json.dumps(doc, ensure_ascii=False).encode("utf-8")
    for label, password in (("current", CATALOG_PASSWORD), ("legacy", BUNDLED_PASSWORD)):
        blob = _encrypt_blob(raw, password, salt, nonce)
        try:
            check(f"round-trip catalog ({label} password)", decode(blob, passwords=(password,)) == doc)
        except DecodeError:
            check(f"round-trip catalog ({label} password)", False)
    blob = _encrypt_blob(raw, CATALOG_PASSWORD, salt, nonce)
    bad = bytearray(base64.b64decode(blob))
    bad[-1] ^= 0x01
    try:
        decode(base64.b64encode(bytes(bad)).decode("ascii"))
        check("tampered GCM tag rejected", False)
    except DecodeError as exc:
        check("tampered GCM tag rejected", exc.code == "DECRYPT_FAILED")
    passed = sum(cases)
    print(json.dumps({"self_test": "pass" if passed == len(cases) else "fail",
                      "passed": passed, "total": len(cases)}, ensure_ascii=False))
    return 0 if passed == len(cases) else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path, help="Respuesta del catálogo guardada localmente")
    source.add_argument("--url", nargs="?", const=CATALOG_URL,
                        help="Descarga explícita; por defecto usa el endpoint original")
    source.add_argument("--apks", type=Path, metavar="APK",
                        help="Lee assets/configfile.json del APK indicado")
    source.add_argument("--stdin", action="store_true", help="Lee la respuesta cifrada desde stdin")
    source.add_argument("--self-test", action="store_true",
                        help="Round-trip sintético (cifrar -> descifrar); no usa archivos reales ni red")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo; no sobrescribe")
    parser.add_argument("--summary", action="store_true",
                        help="Solo recuentos (versión y tamaños de lista), sin valores descifrados")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    try:
        if args.url is not None:
            raw = fetch_catalog(args.url)
        elif args.apks is not None:
            raw = read_bundled(args.apks)
        elif args.stdin:
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
        else:
            raw = _read_file(args.file)
        # The bundled asset uses the legacy password; try it first there.
        passwords = (BUNDLED_PASSWORD, CATALOG_PASSWORD) if args.apks is not None else (CATALOG_PASSWORD, BUNDLED_PASSWORD)
        doc = decode(raw, passwords=passwords)
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
