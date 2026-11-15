#!/usr/bin/env python3
"""AT NET VPN v1.9.28.1: catalog decoder, local or explicit HTTPS.

Python 3.10+, solo biblioteca estándar: Argon2id (RFC 9106) y AES-256-GCM
están implementados en Python puro en este archivo (verificados contra
argon2-cffi y PyCryptodome). Un descifrado tarda ~15-20 s.
Package com.technore.atnetvpn, versionCode 103, versionName v1.9.28.1.

Catalog source recovered from the Go core (libgojni.so, AndroidLibXrayLite):
the app checks for updates with CU() and downloads the catalog with a POST,
not a GET. The exact request, as the app builds it in CU()
(github.com/2dust/AndroidLibXrayLite.CU, libgojni.so):

    POST https://strongteam.co/api/atnetvpn/
    Content-Type: application/x-www-form-urlencoded
    User-Agent: Go-http-client/1.1
    Body (url.Values, one field): hash=xsandokBCUpdatex

No auth, no cookies, no extra headers. The server answers HTTP 200,
Content-Type text/plain, gzip-compressed; the body is a single line of
Base64 (942185 bytes on 2026-11-13 for AT NET; RNV Tunnel VPN's
capture the same day was 942201 bytes, so the live body varies slightly
between requests). The body is one Argon2id + AES-256-GCM envelope (the same
envelope the app's Encrypt() produces):

    Base64( salt[16] || nonce[12] || AES-256-GCM(key, nonce, AAD=salt) )
    key = Argon2id(password, salt, time=3, memory=8192 KiB, threads=1, 32 B)

Two 32-byte passwords live in libgojni.so .rodata (adjacent constants):
  K1 "55wM74DfCDIEaQ7nZPvsGmbw8qq6UFAh" -- used by decrypt()/Encrypt(),
     i.e. the live catalog path (CU calls decrypt on the HTTP response).
  K2 "VENghqlinlpXUH5iVjNtL51WUqoeq/qB" -- used by DO()/do_(), i.e. the
     bundled asset and the .atnet file strings (Hometab.Companion.a).
This decoder tries K1 first, then K2, and reports which key opened the
envelope. The decrypted JSON is the Sandok/Ultra-family schema:
Version (str), ReleaseNotes, Telegram, WhatsApp, Facebook, DefOVPNUser,
DefOVPNPass, HysteriaUser, HysteriaOBFS, DefaultOVPNCert, isTimerOn,
timetoadd, Servers[] and Networks[] (NOT the XXTEA-family
Free_servers/Payloads schema of the other providers).

Bundled asset assets/configfile.json opens with K2 (verified: GCM tag
authenticates, JSON parses, Version "1.01", 1 Server, 1 Network).

LIVE STATUS (2026-11-13, verified for AT NET VPN v1.9.28.1 build 103):
the endpoint above answers HTTP 200 with the 942185-byte Base64 body
(SHA-256 950062e7ffdc0a36f0629591b397e36ae5c0b0c932db63c84de02cb6355abb46),
but that live body does NOT verify with K1 nor K2 (nor Argon2i,
ChaCha20-Poly1305, XXTEA/Princie!, scrypt, alternative salt/nonce
layouts, or an Argon2 parameter grid -- the same variants tried for RNV
Tunnel VPN v1.9.28.1, whose capture the same day was 942201 bytes,
SHA-256 f69ecdaf...). The server appears to have rotated the
live-catalog key/format after this APK version, or the live payload uses
a key not present in v1.9.28.1. This script therefore reports the live
download honestly (size + "LIVE_DECRYPT_FAILED") instead of pretending
it opened, and it still opens any K1/K2 envelope -- the bundled asset
and any future live payload encrypted with the app keys. If the server
returns a K1/K2 payload again, this script opens it unchanged. A real
.atnet file exported by the app is still needed to confirm the file
decoder end to end (see AT_NET_VPN_archivos.py).
Note: Cloudflare truncates the chunked body on about half the requests
(http.client.IncompleteRead) and ignores Range on this POST endpoint, so
fetch_catalog() retries the whole POST until a complete body arrives.

The icon URL is separate and unrelated to the catalog:
https://strongteam.co/nets/<icon name> (NetworkIconCache, Java).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import hashlib
import struct
import json
import math
from http.client import HTTPException
from pathlib import Path
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

MAX_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1

CATALOG_URL = "https://strongteam.co/api/atnetvpn/"
# Exact form body the app sends (url.Values with the single field "hash").
FORM_BODY = b"hash=xsandokBCUpdatex"
# Exact headers the app sends (Go net/http default User-Agent + the
# Content-Type CU sets on the request).
USER_AGENT = "Go-http-client/1.1"
CONTENT_TYPE = "application/x-www-form-urlencoded"
# Argon2id parameters, fixed in the Go core (decrypt/DO/Encrypt).
ARGON_TIME = 3
ARGON_MEMORY_KIB = 8192
ARGON_THREADS = 1
ARGON_KEY_LEN = 32
# The two 32-byte format passwords in this APK's libgojni.so
# (file offsets 0x365dee, 0x365e0e; RNV Tunnel VPN v1.9.28.1 has the
# same two constants at file offsets 0x365df4, 0x365e14).
# They are app format constants, not account credentials.
KEY_LIVE = b"55wM74DfCDIEaQ7nZPvsGmbw8qq6UFAh"   # K1: decrypt()/Encrypt()
KEY_BUNDLED = b"VENghqlinlpXUH5iVjNtL51WUqoeq/qB"  # K2: DO()/do_()
LIST_FIELDS = ("Servers", "Networks")


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


def _base64_candidates(text: str) -> list[bytes]:
    """Decode the Base64 body. The live response is 1 byte longer than a
    multiple of 4 (942185 bytes on 2026-11-13); try the body as-is first,
    then dropping a leading/trailing byte, and return every decoding.
    Duplicate decodings (same bytes) are returned only once."""
    compact = re.sub(r"[ \t\r\n]", "", text)
    out: list[bytes] = []
    seen: set[bytes] = set()
    for cand in (compact, compact[1:], compact[:-1]):
        if not cand or len(cand) % 4 == 1:
            continue
        if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", cand):
            continue
        try:
            blob = base64.b64decode(cand + "=" * (-len(cand) % 4), validate=True)
        except (ValueError, binascii.Error):
            continue
        if blob not in seen:
            seen.add(blob)
            out.append(blob)
    if not out:
        raise DecodeError("FORMAT_ERROR", "Se esperaba Base64 estándar del catálogo.")
    return out



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


def decrypt_envelope(blob: bytes) -> tuple[bytes, str]:
    """Open one Argon2id + AES-256-GCM envelope. Returns (plaintext, key name).
    Tries K1 (live) then K2 (bundled/files). Pure stdlib crypto."""
    if len(blob) < 44:
        raise DecodeError("TRUNCATED", "El sobre cifrado es demasiado corto (mínimo 44 bytes).")
    salt, nonce, rest = blob[:16], blob[16:28], blob[28:]
    ciphertext, tag = rest[:-16], rest[-16:]
    for password, name in ((KEY_LIVE, "K1"), (KEY_BUNDLED, "K2")):
        key = _argon2id(password, salt, time_cost=ARGON_TIME,
                        memory_kib=ARGON_MEMORY_KIB, parallelism=ARGON_THREADS,
                        tag_len=ARGON_KEY_LEN)
        try:
            return _aes_gcm_decrypt(key, nonce, ciphertext, tag, aad=salt), name
        except ValueError:
            continue
    raise DecodeError(
        "LIVE_DECRYPT_FAILED",
        "El cuerpo remoto no verifica con K1 ni K2 (ni con las variantes "
        "probadas: Argon2i, ChaCha20-Poly1305, XXTEA, scrypt ni otros layouts). "
        "El servidor parece haber rotado la clave del catálogo en vivo.",
    )


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


def _catalog_json(data: bytes) -> dict:
    doc = _json(data)
    if not isinstance(doc.get("Version"), str) or not doc["Version"]:
        raise DecodeError("WRONG_DOCUMENT", "El catálogo no trae una Version válida.")
    if any(not isinstance(doc.get(k), list) for k in LIST_FIELDS):
        raise DecodeError("WRONG_DOCUMENT", "Faltan las listas Servers o Networks del catálogo.")
    if not any(doc[k] for k in LIST_FIELDS):
        raise DecodeError("WRONG_DOCUMENT", "El catálogo no trae servidores ni redes.")
    return doc


def decode(data: bytes | str) -> dict:
    """Offline API: decrypt the complete catalog envelope and return the dict.
    Accepts the raw HTTP body (Base64 text) or a local asset (configfile.json)."""
    text = _text(data)
    if text.startswith("{"):
        return _catalog_json(text.encode("utf-8"))
    last_error: DecodeError | None = None
    for blob in _base64_candidates(text):
        try:
            plain, _key = decrypt_envelope(blob)
            return _catalog_json(plain)
        except DecodeError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise DecodeError("DECRYPT_FAILED", "No se pudo descifrar el catálogo.")


def decode_with_key(data: bytes | str) -> tuple[dict, str]:
    """Like decode(), but also returns which key opened the envelope ("K1"/"K2")."""
    text = _text(data)
    if text.startswith("{"):
        return _catalog_json(text.encode("utf-8")), "plain"
    last_error: DecodeError | None = None
    for blob in _base64_candidates(text):
        try:
            plain, key = decrypt_envelope(blob)
            return _catalog_json(plain), key
        except DecodeError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise DecodeError("DECRYPT_FAILED", "No se pudo descifrar el catálogo.")


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


def _proxy_for(host: str):
    """Return (proxy_host, proxy_port, proxy_auth) from the environment, or
    None for a direct connection. Respects no_proxy."""
    import os
    from urllib.parse import urlsplit as _split
    no_proxy = os.environ.get("no_proxy", "") or os.environ.get("NO_PROXY", "")
    for entry in [e.strip().lower() for e in no_proxy.split(",") if e.strip()]:
        if host.lower() == entry or host.lower().endswith("." + entry.lstrip(".")):
            return None
    raw = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY") or ""
    if not raw:
        return None
    parsed = _split(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    auth = None
    if parsed.username:
        import base64 as _b64
        auth = _b64.b64encode(
            f"{parsed.username}:{parsed.password or ''}".encode("utf-8")).decode("ascii")
    return parsed.hostname, parsed.port or 3128, auth


def fetch_catalog(url: str = CATALOG_URL, retries: int = 8) -> bytes:
    """POST exactly as the app does (CU): form hash=xsandokBCUpdatex,
    Content-Type form-urlencoded, Go User-Agent, no auth. The response is
    deterministic. Implemented with http.client (not urllib): in this
    environment urllib's opener truncates the chunked body on most
    requests (http.client.IncompleteRead at ~500 KiB) while http.client
    with an explicit proxy CONNECT tunnel completes it every time.
    Cloudflare ignores Range on this POST endpoint, so resume-by-ranges
    does not apply; instead the whole POST is retried until a complete
    body arrives."""
    parsed = _https_url(url)
    host = parsed.hostname
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    last_error: Exception | None = None
    for attempt in range(max(1, retries)):
        try:
            import http.client as _http
            import ssl as _ssl
            proxy = _proxy_for(host)
            if proxy is not None:
                proxy_host, proxy_port, proxy_auth = proxy
                conn = _http.HTTPConnection(proxy_host, proxy_port, timeout=30)
                tunnel_headers = {}
                if proxy_auth:
                    tunnel_headers["Proxy-Authorization"] = "Basic " + proxy_auth
                tunnel_headers["Proxy-Connection"] = "Keep-Alive"
                conn.set_tunnel(host, 443, headers=tunnel_headers)
                conn.connect()
                conn.sock = _ssl.create_default_context().wrap_socket(
                    conn.sock, server_hostname=host)
            else:
                conn = _http.HTTPSConnection(host, 443, timeout=30)
            try:
                conn.putrequest("POST", path, skip_host=False, skip_accept_encoding=False)
                conn.putheader("Host", host)
                conn.putheader("User-Agent", USER_AGENT)
                conn.putheader("Content-Type", CONTENT_TYPE)
                conn.putheader("Accept-Encoding", "gzip")
                conn.putheader("Content-Length", str(len(FORM_BODY)))
                conn.endheaders(FORM_BODY)
                resp = conn.getresponse()
                if resp.status != 200:
                    raise OSError("unexpected HTTP status")
                raw = resp.read(MAX_BYTES + 1)
                if resp.getheader("Content-Encoding", "identity") == "gzip":
                    raw = gzip.decompress(raw)
            finally:
                conn.close()
        except HTTPError as exc:
            code = "ACCESS_DENIED" if exc.code in (401, 403) else "DOWNLOAD_FAILED"
            raise DecodeError(code, "El endpoint no devolvió un catálogo accesible.") from exc
        except (OSError, ValueError, URLError, HTTPException, gzip.BadGzipFile) as exc:
            last_error = exc
            if attempt + 1 < max(1, retries):
                import time
                time.sleep(1 + attempt)
            continue
        if not raw or len(raw) > MAX_BYTES or raw.lstrip().startswith(b"<"):
            raise DecodeError("DOWNLOAD_FAILED", "Catálogo vacío, incompatible o superior a 8 MiB.")
        return raw
    raise DecodeError("DOWNLOAD_FAILED", "No se pudo descargar el catálogo mediante HTTPS.") from last_error


def _read(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=False)
    source.add_argument("file", nargs="?", type=Path,
                        help="Respuesta del catálogo guardada localmente (también acepta el asset configfile.json)")
    source.add_argument("--url", nargs="?", const=CATALOG_URL,
                        help="Descarga explícita; por defecto usa el endpoint original")
    source.add_argument("--stdin", action="store_true", help="Leer la respuesta cifrada desde stdin")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo; por defecto stdout")
    parser.add_argument("--self-test", action="store_true",
                        help="Verifica el sobre con el asset incluido (requiere configfile.json junto al script)")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            asset = Path(__file__).with_name("configfile.json")
            if not asset.exists():
                print(json.dumps({"error": "SELF_TEST_NO_ASSET",
                                  "message": "configfile.json no está junto al script."},
                                 ensure_ascii=False), file=sys.stderr)
                return 2
            doc, key = decode_with_key(_read(asset))
            print(json.dumps({"self_test": "OK", "key": key, "version": doc.get("Version"),
                              "servers": len(doc.get("Servers", [])),
                              "networks": len(doc.get("Networks", []))}, ensure_ascii=False))
            return 0
        if args.url is not None:
            raw = fetch_catalog(args.url)
        elif args.stdin:
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        elif args.file is not None:
            raw = _read(args.file)
        else:
            parser.error("se requiere un archivo, --url o --stdin (o --self-test)")
        doc, key = decode_with_key(raw)
        rendered = json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        print(json.dumps({"key": key, "version": doc.get("Version"),
                          "servers": len(doc.get("Servers", [])),
                          "networks": len(doc.get("Networks", []))},
                         ensure_ascii=False), file=sys.stderr)
        return 0
    except DecodeError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR", "message": "No se pudo leer o escribir el archivo."}),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
