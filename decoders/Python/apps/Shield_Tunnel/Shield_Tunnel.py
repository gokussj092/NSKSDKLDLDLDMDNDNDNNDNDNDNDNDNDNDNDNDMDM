#!/usr/bin/env python3
"""Shield Tunnel / One Shield Tunnel v1.11.06.1: catalog decoder, local or explicit HTTPS.

Python 3.10+, solo biblioteca estandar: Argon2id (RFC 9106) y AES-256-GCM
estan implementados en Python puro en este archivo (verificados contra
argon2-cffi y PyCryptodome). Un descifrado del sobre tarda ~30-40 s
(Argon2id con memoria 16384 KiB).
Package one.shield.tunnel, versionCode 79, versionName v1.11.06.1. En
Google Play y APKPure figura como "One Shield Tunnel" (desarrollador
sando--k). Fork de v2rayNG (com.v2ray.ang) con nucleo Sandok/Ultra
(AndroidLibXrayLite, Go 1.20) y cadenas ofuscadas con LSParanoid
(Deobfuscator$OneShieldTunnel$app, 21 chunks, 8,229 call sites;
resueltas con el port verificado de RNV; RandomHelper.next()/seed()
verificados byte a byte identicos a Marvs/RNV).

Catalog source recovered from the Go core (libgojni.so, AndroidLibXrayLite):
the app checks for updates with CU() and downloads the catalog with a POST,
not a GET. The exact request, as the app builds it in CU()
(github.com/2dust/AndroidLibXrayLite.CU, libgojni.so):

    POST https://strongteam.co/api/oneshieldtunnel/
    Content-Type: application/x-www-form-urlencoded
    User-Agent: Go-http-client/1.1
    Body (url.Values, one field): hash=xsandokUpdatex

No auth, no cookies, no extra headers. The server answers HTTP 200,
Content-Type text/plain; charset=utf-8, chunked. The body is a single line
of Base64 (668,772 bytes on 2026-11-14, SHA-256
262d8a20f5524c13ea2bb76e4c8fd2e5c6f8438d6569536c688d1c8b99e6ddaa).
The body is one Argon2id + AES-256-GCM envelope (the same envelope the
app's Encrypt() produces):

    Base64( salt[16] || nonce[12] || AES-256-GCM(key, nonce, AAD=salt) )
    key = Argon2id(password, salt, time=3, memory=16384 KiB, threads=1, 32 B)

Two format passwords are built by the Go core (disassembly of decrypt()
and DO() in libgojni.so; each loads 16 bytes from .rodata and overwrites
the tail with movk immediates):
  K1 "NewDecryptLibPasswordII" (23 bytes) -- used by decrypt()/Encrypt(),
     i.e. the live catalog path (CU calls decrypt on the HTTP response).
     .rodata offset 0x3564a9 (16 bytes) + "sswordII" (movk).
  K2 "NewDecryptLibPassword" (21 bytes) -- used by DO()/do_(), i.e. the
     bundled asset and the file strings. .rodata offset 0x3534bb
     (16 bytes) + "Password" (movk, stored at offset 13).
This decoder tries K1 first, then K2, and reports which key opened the
envelope. The decrypted JSON is the Sandok/Ultra-family schema:
Version (str), ReleaseNotes, Telegram, WhatsApp, Facebook, DefOVPNUser,
DefOVPNPass, HysteriaUser, HysteriaOBFS, DefaultOVPNCert, isTimerOn,
timetoadd, Servers[] and Networks[] (NOT the XXTEA-family
Free_servers/Payloads schema of the other providers). The catalog has
NO free/premium distinction (no Category field): all servers are listed
together.

FIELD ENCRYPTION: most string values inside Servers[]/Networks[] are
themselves the same envelope (Base64(salt||nonce||GCM), Argon2id
m=16384) and open with K2 -- verified on the live catalog 2026-11-14:
every Base64 field that parses as an envelope (44+ bytes) opened with
K2, 0 failures (Servers: 32/32 ServerIPHost, 32/32 SlowDNSKey, 32/32
UDP_obfs; Networks: 418/418 V2rayAddress, 418/418 V2raySNI, 418/418
Payload, 42+376 V2rayConfig, etc.; empty plaintexts are normal for
fields the server leaves blank, e.g. OVPNUser when isdefUser=true).
Plaintext fields (Name, Flag, ports, TunnelType, BugDNS...) are left
as-is. decode() returns the catalog with the field blobs as they come
from the server (same convention as the RNV/Marvs scripts), because
each field needs its own Argon2id run (~30 s in pure Python, ~0.3 s
with argon2-cffi) and bulk field decryption is impractical here;
decrypt_field() below opens a single field with K2 for callers that
need the clear value (server host, user, password, payload, SNI...).

LIVE STATUS (2026-11-14): the endpoint above answers HTTP 200 and the
live body OPENS with K1 (Version "7.15", 32 servers, 440 networks,
433 with Payload). Unlike Marvs SSH / T20-VPN, RNV and AT NET (same
StrongTeam family), Shield Tunnel's live key has NOT rotated: the
catalog is fully live and current. Note: urllib truncates the chunked
body on most requests (IncompleteRead at ~500 KiB); http.client with an
explicit proxy CONNECT tunnel (set_tunnel) completes it every time, and
Cloudflare ignores Range on this POST endpoint, so resume-by-ranges
does not apply.

Bundled asset assets/configfile.json opens with K2 (verified: GCM tag
authenticates, JSON parses, Version "1.01", 34 Servers, 555 Networks).

The icon URL is separate and unrelated to the catalog:
https://strongteam.co/nets/<icon name> (NetworkIconCache, Java).

Repo: SP-DECODE has NO prior coverage of one.shield.tunnel (checked
2026-11-14 on feat/nuevas-integraciones, 86 app folders). This app is
NOT Shield VPN (litron.shield.vpn, batch 7) nor Guruz Tunnel (batch 8):
different package, different endpoint, different keys -- nothing was
reused from them without verifying it in THIS APK (Shield uses Argon2
memory 16384 KiB, verified by disassembly + GCM tag on the asset and
on the live body; Marvs/RNV use 8192 KiB).
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

CATALOG_URL = "https://strongteam.co/api/oneshieldtunnel/"
# Exact form body the app sends (url.Values with the single field "hash").
FORM_BODY = b"hash=xsandokUpdatex"
# Exact headers the app sends (Go net/http default User-Agent + the
# Content-Type CU sets on the request).
USER_AGENT = "Go-http-client/1.1"
CONTENT_TYPE = "application/x-www-form-urlencoded"
# Argon2id parameters, fixed in the Go core (decrypt/DO/Encrypt).
ARGON_TIME = 3
ARGON_MEMORY_KIB = 16384
ARGON_THREADS = 1
ARGON_KEY_LEN = 32
# The two 32-byte format passwords in libgojni.so .rodata (adjacent
# constants, .rodata offsets 0x365e07 and 0x365e27).
# They are app format constants, not account credentials.
KEY_LIVE = b"NewDecryptLibPasswordII"   # K1: decrypt()/Encrypt()
KEY_BUNDLED = b"NewDecryptLibPassword"  # K2: DO()/do_()
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
    """Decode the Base64 body. The live response is 668772 bytes on
    2026-11-14 (668772 Base64 chars, no trailing newline); try the body
    as-is first, then dropping a leading/trailing byte, and return every
    decoding. Duplicate decodings (same bytes) are returned only once."""
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
    key = _argon2id(password, salt, time_cost=3, memory_kib=16384,
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
        "El sobre no verifica con K1 ni K2 (ni con las variantes "
        "probadas: Argon2i, Argon2id m=8192, ni las claves K1/K2 de "
        "RNV/ATNET/Marvs). El servidor parece haber rotado la clave "
        "del catalogo en vivo.",
    )


def decrypt_field(value: str) -> str | None:
    """Open ONE catalog field value (ServerIPHost, OVPNUser, Payload, SNI,
    V2rayConfig, ...) with K2. Returns the clear text, "" when the field
    is a valid envelope of an empty plaintext, or None when the value is
    not an envelope at all (plaintext field) or does not verify. Each
    call needs its own Argon2id run (~30 s in pure Python here, ~0.3 s
    with argon2-cffi), so bulk field decryption is impractical with this
    script alone; the app decrypts each field lazily at runtime."""
    if not isinstance(value, str) or not value:
        return None
    try:
        blob = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return None
    if len(blob) < 44:
        return None
    salt, nonce, rest = blob[:16], blob[16:28], blob[28:]
    ciphertext, tag = rest[:-16], rest[-16:]
    key = _argon2id(KEY_BUNDLED, salt, time_cost=ARGON_TIME,
                    memory_kib=ARGON_MEMORY_KIB, parallelism=ARGON_THREADS,
                    tag_len=ARGON_KEY_LEN)
    try:
        plain = _aes_gcm_decrypt(key, nonce, ciphertext, tag, aad=salt)
    except ValueError:
        return None
    try:
        return plain.decode("utf-8")
    except UnicodeError:
        return None


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
    """POST exactly as the app does (CU): form hash=xsandokUpdatex,
    Content-Type form-urlencoded, Go User-Agent, no auth. The response is
    deterministic (byte-identical across requests). Implemented with
    http.client (not urllib): in this environment urllib's opener
    truncates the chunked body on most requests (IncompleteRead at
    ~300 KiB) while http.client with an explicit proxy CONNECT tunnel
    (set_tunnel) completes it every time. Cloudflare ignores Range on
    this POST endpoint, so resume-by-ranges does not apply; instead the
    whole POST is retried until a complete body arrives."""
    parsed = _https_url(url)
    host = parsed.hostname
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    last_error: Exception | None = None
    for attempt in range(max(1, retries)):
        try:
            import http.client as _http
            proxy = _proxy_for(host)
            if proxy is not None:
                proxy_host, proxy_port, proxy_auth = proxy
                conn = _http.HTTPSConnection(proxy_host, proxy_port, timeout=30)
                tunnel_headers = {}
                if proxy_auth:
                    tunnel_headers["Proxy-Authorization"] = "Basic " + proxy_auth
                conn.set_tunnel(host, 443, headers=tunnel_headers)
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
