#!/usr/bin/env python3
"""MM Tunnel (Marvs UDP) v1.11.06.1: catalog decoder, local or explicit HTTPS.

Python 3.10+, solo biblioteca estandar para el sobre del catalogo:
Argon2id (RFC 9106) y AES-256-GCM estan implementados en Python puro en
este archivo (verificados contra argon2-cffi y PyCryptodome). Un
descifrado del sobre (m=16384) tarda ~90 s en stdlib puro; con
argon2-cffi + PyCryptodome, ~0,3 s.
Package co.strongteam.marvsudp, versionCode 48, versionName v1.11.06.1.
En Google Play y APKPure figura como "MM Tunnel" (desarrollador
sando--k). Fork de v2rayNG (com.v2ray.ang) con nucleo Sandok/Ultra
(AndroidLibXrayLite, Go) y cadenas ofuscadas con LSParanoid
(Deobfuscator$MMTunnel$app). Hermana de Marvs SSH / T20-VPN
(vpn.marvs.ssh): mismo esquema de sobre y mismo cuerpo de peticion,
pero OTRO endpoint (POST https://strongteam.co/api/mmtunnel/) y OTRAS
claves; a diferencia de Marvs SSH, su catalogo en vivo SI abre con las
claves de este APK (la clave en vivo no esta rotada).

Catalog source recovered from the Go core (libgojni.so, byte-identical
to the build 45/47 library): the app checks for updates with CU() and
downloads the catalog with a POST, not a GET. The exact request, as the
app builds it in CU() (github.com/2dust/AndroidLibXrayLite.CU,
libgojni.so):

    POST https://strongteam.co/api/mmtunnel/
    Content-Type: application/x-www-form-urlencoded
    User-Agent: Go-http-client/1.1
    Body (url.Values, one field): hash=xsandokUpdatex

No auth, no cookies, no extra headers. The server answers HTTP 200,
Content-Type text/plain; charset=utf-8, chunked. The body is a single
line of Base64 (1,154,861 bytes on 2026-11-14, SHA-256
e94bb7420c32325844079a9528266e285db0f9e095c3768ef091c39834e26773). The
body is one Argon2id + AES-256-GCM envelope (the same envelope the
app's Encrypt() produces), with one random ASCII letter inserted at
Base64 index 3 AFTER encoding:

    Base64( salt[16] || nonce[12] || AES-256-GCM(key, nonce, AAD=salt) )
    key = Argon2id(password, salt, time=3, memory=16384 KiB, threads=1, 32 B)

Two format passwords live in libgojni.so .rodata (recovered by
disassembly of THIS APK's libgojni.so and verified by opening the real
envelopes):
  FILE_SECRET = "iOi/hqT/TocUv0UbDImfWPGR1mfSdzzX" -- Encrypt()/decrypt(),
     i.e. the live catalog path and exported .mmt files. .rodata 0x365e74.
  FIELD_SECRET = "NewDecryptLibPassword" -- EO()/DO(), i.e. the bundled
     asset configfile.json and every protected field inside the catalog.
     Built in EO 0x10129d0 / DO 0x1012df0 from .rodata 0x353439
     ("NewDecryptLibPass", 16 B) + "Password" (movk-immediate).
This decoder tries the marker-stripped FILE envelope first, then the
plain FIELD envelope, and reports which key opened it. The decrypted
JSON is the Sandok/Ultra-family schema: Version (str), ReleaseNotes,
Telegram, WhatsApp, Facebook, DefOVPNUser, DefOVPNPass, HysteriaUser,
HysteriaOBFS, DefaultOVPNCert, isTimerOn, timetoadd, Servers[] and
Networks[] (NOT the XXTEA-family Free_servers/Payloads schema of the
other providers). No free/premium marker exists in the data: all 37
servers come in a single list.

Bundled asset assets/configfile.json opens plain with FIELD_SECRET
(verified: GCM tag authenticates, JSON parses, Version "1.01",
34 Servers, 555 Networks, 3,335 unique field envelopes).

LIVE STATUS (2026-11-14): the endpoint above answers HTTP 200 with the
1,154,861-byte Base64 body, which opens with FILE_SECRET
(marker-stripped): Version "2.71", ReleaseNotes "Servers FIX & FIX
GCP", 37 Servers, 818 Networks, 3,464 unique field envelopes.
Note: urllib truncates the chunked body on most requests
(IncompleteRead at ~300 KiB); http.client with an explicit proxy
CONNECT tunnel (set_tunnel) completes it every time, and Cloudflare
ignores Range on this POST endpoint, so resume-by-ranges does not apply.

Field envelopes: each protected field (DefOVPNUser, DefOVPNPass,
HysteriaUser, HysteriaOBFS, DefaultOVPNCert; ServerIPHost, OVPNUser,
OVPNPass, UDP_obfs, UDP_user, CustomCertificate, SlowDNSHost,
SlowDNSKey, V2rayUUID, H2pass, TrojanPass, V2rayPath; Payload,
CustomProxy, SNI, V2rayConfig, BugDNS, V2rayAddress, V2rayHost,
V2raySNI) is itself an EO envelope (FIELD_SECRET, Argon2id m=16384 +
AES-256-GCM, AAD=salt). Only Base64-shaped values >= 60 chars are
envelopes; shorter values are plaintext. By default this script does
NOT decode the fields (3,464 envelopes x ~88 s in pure stdlib is
infeasible); pass --fields to decode them all, which requires
argon2-cffi + PyCryptodome (fast path, ~0.3 s each, parallelizable
with --workers). Field decoding fails closed: a single bad tag aborts
the whole document instead of returning partial credentials.
Known exception, verified 2026-11-14: 37 of the 3,464 live field
envelopes do NOT verify with FIELD_SECRET nor with any tested variant
(FILE_SECRET, NewDecryptLibPasswordIICore, Argon2i, memory 4096-32768,
time 1-3, version 0x10/0x13, AAD salt/none, AES-GCM, ChaCha20-Poly1305,
tag-first layout, direct AES-CBC/ECB). All 37 are Payload (15), SNI
(13) or CustomProxy (9) of 16 Egypt networks (Etisalat/WE); one of
them decodes to only 43 bytes, below the 44-byte minimum of the EO
envelope, so at least some are not EO envelopes at all. This APK's
libgojni.so has no other field-decrypt function besides EO/DO, so
nothing in the APK can open them with the keys present in it. Because
of that, --fields fails closed on the live catalog; use
--fields-partial instead: it decodes the 3,427 envelopes that open and
leaves the 37 encoded as-is, reporting each by location.

The icon URL is separate and unrelated to the catalog:
https://strongteam.co/nets/<icon name> (NetworkIconCache, Java).

Repo: SP-DECODE already covers co.strongteam.marvsudp in
decoders/Python/apps/MM_Tunnel/ (build 47, v1.10.30.2, live 2.46,
38/557). This delivery re-verifies everything in THIS APK (build 48,
v1.11.06.1): same endpoint, same keys, same libgojni.so (byte-identical
to build 45), same bundled asset; live catalog updated to 2.71,
37/818. Nothing was reused from the repo or from Marvs SSH without
verifying it in THIS APK (Marvs SSH uses Argon2 memory 8192 KiB and
different keys K1/K2; MM Tunnel uses 16384 KiB and FILE/FIELD secrets).
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

CATALOG_URL = "https://strongteam.co/api/mmtunnel/"
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
# The two format passwords in libgojni.so .rodata, recovered by disassembly
# of THIS APK's libgojni.so and verified by opening the real envelopes.
# They are app format constants, not account credentials.
FILE_SECRET = b"iOi/hqT/TocUv0UbDImfWPGR1mfSdzzX"  # Encrypt()/decrypt(), .rodata 0x365e74
FIELD_SECRET = b"NewDecryptLibPassword"  # EO()/DO(), .rodata 0x353439 + "Password"

# Fast path for field decoding (argon2-cffi + PyCryptodome). The pure
# stdlib Argon2id below needs ~88 s per envelope at m=16384, so decoding
# the 3,464 field envelopes is only feasible with the fast path.
try:
    from argon2.low_level import Type as _Argon2Type, hash_secret_raw as _argon2_fast
    from Crypto.Cipher import AES as _AES_FAST
    _FAST_CRYPTO = True
except Exception:  # pragma: no cover - optional dependency
    _FAST_CRYPTO = False

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
    """Inverse of decrypt_envelope (mirrors AndroidLibXrayLite.Encrypt)."""
    if _FAST_CRYPTO:
        key = _argon2_fast(password, salt, time_cost=ARGON_TIME,
                           memory_cost=ARGON_MEMORY_KIB, parallelism=ARGON_THREADS,
                           hash_len=ARGON_KEY_LEN, type=_Argon2Type.ID, version=19)
        cipher = _AES_FAST.new(key, _AES_FAST.MODE_GCM, nonce=nonce)
        cipher.update(salt)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return base64.b64encode(salt + nonce + ciphertext + tag).decode("ascii")
    key = _argon2id(password, salt, time_cost=ARGON_TIME,
                    memory_kib=ARGON_MEMORY_KIB, parallelism=ARGON_THREADS,
                    tag_len=ARGON_KEY_LEN)
    ciphertext, tag = _aes_gcm_encrypt(key, nonce, plaintext, aad=salt)
    return base64.b64encode(salt + nonce + ciphertext + tag).decode("ascii")


def decrypt_envelope(blob: bytes, password: bytes) -> bytes:
    """Open one Argon2id + AES-256-GCM envelope with the given password.
    Fast path (~0.3 s) when argon2-cffi + PyCryptodome are available,
    otherwise pure stdlib (~88 s at m=16384)."""
    if len(blob) < 44:
        raise DecodeError("TRUNCATED", "El sobre cifrado es demasiado corto (mínimo 44 bytes).")
    salt, nonce, rest = blob[:16], blob[16:28], blob[28:]
    ciphertext, tag = rest[:-16], rest[-16:]
    if _FAST_CRYPTO:
        key = _argon2_fast(password, salt, time_cost=ARGON_TIME,
                           memory_cost=ARGON_MEMORY_KIB, parallelism=ARGON_THREADS,
                           hash_len=ARGON_KEY_LEN, type=_Argon2Type.ID, version=19)
        cipher = _AES_FAST.new(key, _AES_FAST.MODE_GCM, nonce=nonce)
        cipher.update(salt)
        try:
            return cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as exc:
            raise DecodeError("DECRYPT_FAILED", "El tag GCM no verifica con esta clave.") from exc
    key = _argon2id(password, salt, time_cost=ARGON_TIME,
                    memory_kib=ARGON_MEMORY_KIB, parallelism=ARGON_THREADS,
                    tag_len=ARGON_KEY_LEN)
    try:
        return _aes_gcm_decrypt(key, nonce, ciphertext, tag, aad=salt)
    except ValueError as exc:
        raise DecodeError("DECRYPT_FAILED", "El tag GCM no verifica con esta clave.") from exc


def _envelope_attempts(compact: str) -> list[tuple[bytes, bytes, str]]:
    """Candidate (blob, password, key name) attempts, cheapest-first.
    The app's Encrypt() inserts one random ASCII letter at Base64 index 3
    AFTER encoding, so an exported/live body has length 1 (mod 4); the
    bundled asset has length 0 (mod 4) and no marker."""
    def _b64(s):
        if not s or len(s) % 4 == 1:
            return None
        if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s):
            return None
        try:
            blob = base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
        except (ValueError, binascii.Error):
            return None
        return blob if len(blob) >= 44 else None

    plain = _b64(compact)
    marker = (len(compact) % 4 == 1 and len(compact) > 3
              and compact[3] in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
    stripped = _b64(compact[:3] + compact[4:]) if marker else None
    attempts: list[tuple[bytes, bytes, str]] = []
    if marker and stripped is not None:
        attempts.append((stripped, FILE_SECRET, "FILE"))
    if plain is not None:
        if marker:
            attempts.append((plain, FIELD_SECRET, "FIELD"))
            attempts.append((plain, FILE_SECRET, "FILE"))
        else:
            attempts.append((plain, FIELD_SECRET, "FIELD"))
            attempts.append((plain, FILE_SECRET, "FILE"))
            if stripped is not None:
                attempts.append((stripped, FILE_SECRET, "FILE"))
    if not attempts:
        raise DecodeError("FORMAT_ERROR", "Se esperaba Base64 estándar del catálogo.")
    return attempts


def open_envelope_text(text: str) -> tuple[bytes, str]:
    """Open one catalog envelope. Returns (plaintext, key name). The
    marker heuristic keeps the pure-stdlib path to one Argon2id (~88 s)
    in the common cases instead of three."""
    compact = re.sub(r"[ \t\r\n]", "", text)
    for blob, password, name in _envelope_attempts(compact):
        try:
            return decrypt_envelope(blob, password), name
        except DecodeError:
            continue
    raise DecodeError(
        "DECRYPT_FAILED",
        "El cuerpo remoto no verifica con FILE_SECRET ni FIELD_SECRET "
        "(ni con/sin la letra marcadora). Si el servidor rotó la clave "
        "del catálogo en vivo, hace falta el APK actualizado.",
    )


# ------------------------------------------------------- Field envelopes
TOP_FIELDS = frozenset({
    "DefOVPNUser", "DefOVPNPass", "HysteriaUser", "HysteriaOBFS", "DefaultOVPNCert",
})
SERVER_FIELDS = frozenset({
    "ServerIPHost", "OVPNUser", "OVPNPass", "UDP_obfs", "UDP_user", "CustomCertificate",
    "SlowDNSHost", "SlowDNSKey", "V2rayUUID", "H2pass", "TrojanPass", "V2rayPath",
})
NETWORK_FIELDS = frozenset({
    "Payload", "CustomProxy", "SNI", "V2rayConfig", "BugDNS", "V2rayAddress",
    "V2rayHost", "V2raySNI",
})


def _is_field_envelope(value) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.replace("\r", "").replace("\n", "")
    return len(normalized) >= 60 and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", normalized) is not None


def _open_field_fast(value: str) -> str:
    """Open one EO field envelope (FIELD_SECRET). Fast path only."""
    raw = base64.b64decode(value.replace("\r", "").replace("\n", ""), validate=True)
    salt, nonce = raw[:16], raw[16:28]
    key = _argon2_fast(FIELD_SECRET, salt, time_cost=ARGON_TIME,
                       memory_cost=ARGON_MEMORY_KIB, parallelism=ARGON_THREADS,
                       hash_len=ARGON_KEY_LEN, type=_Argon2Type.ID, version=19)
    cipher = _AES_FAST.new(key, _AES_FAST.MODE_GCM, nonce=nonce)
    cipher.update(salt)
    return cipher.decrypt_and_verify(raw[28:-16], raw[-16:]).decode("utf-8")


def _decode_one_field(value: str) -> tuple[bool, str | None]:
    """Module-level worker for multiprocessing: (ok, plaintext)."""
    try:
        return True, _open_field_fast(value)
    except Exception:
        return False, None


def decode_fields(doc: dict, workers: int = 0, strict: bool = True) -> tuple[dict, dict]:
    """Decode every protected field envelope in a catalog document.
    Requires argon2-cffi + PyCryptodome: 3,464 envelopes x ~88 s in pure
    stdlib is not viable. In strict mode (default, --fields) it fails
    closed: a single bad tag aborts the whole document instead of
    returning partial credentials. In lenient mode (--fields-partial)
    it decodes every envelope that opens, leaves the ones that fail
    encoded as-is, and reports them by location in the stats. Returns
    (decoded document, stats); never returns credential values here,
    only counts and locations."""
    if not _FAST_CRYPTO:
        raise DecodeError(
            "FAST_CRYPTO_REQUIRED",
            "Decodificar los campos protegidos requiere argon2-cffi y "
            "PyCryptodome (3,464 sobres x ~88 s en stdlib puro no es "
            "viable). Instálalos y repite con --fields.",
        )
    order: list[str] = []
    seen: set[str] = set()
    locations: dict[str, list[str]] = {}

    def collect(value, where):
        if _is_field_envelope(value):
            locations.setdefault(value, []).append(where)
            if value not in seen:
                seen.add(value)
                order.append(value)

    for name in TOP_FIELDS:
        collect(doc.get(name), f"top.{name}")
    for index, record in enumerate(doc.get("Servers", [])):
        for name in SERVER_FIELDS:
            collect(record.get(name), f"server[{index}].{name}")
    for index, record in enumerate(doc.get("Networks", [])):
        for name in NETWORK_FIELDS:
            collect(record.get(name), f"network[{index}].{name}")
    if not order:
        return doc, {"unique": 0, "decoded": 0, "failed": 0, "failed_fields": []}
    if workers and workers > 1:
        from multiprocessing import Pool
        with Pool(processes=workers) as pool:
            results = pool.map(_decode_one_field, order)
    else:
        results = [_decode_one_field(value) for value in order]
    failed = [value for value, (ok, _plain) in zip(order, results) if not ok]
    failed_fields = sorted({loc for value in failed for loc in locations.get(value, [])})
    if failed and strict:
        raise DecodeError(
            "FIELD_DECRYPT_FAILED",
            f"{len(failed)} de {len(order)} campos protegidos no verifican "
            f"el tag GCM (ej. {failed[0][:24]}...). El documento no se "
            "devuelve parcial.",
        )
    plain = {value: text for value, (ok, text) in zip(order, results) if ok}

    def apply(record, names):
        out = record.copy()
        for name in names:
            value = record.get(name)
            if isinstance(value, str) and value in plain:
                out[name] = plain[value]
        return out

    result = apply(doc, TOP_FIELDS)
    result["Servers"] = [apply(record, SERVER_FIELDS) for record in doc.get("Servers", [])]
    result["Networks"] = [apply(record, NETWORK_FIELDS) for record in doc.get("Networks", [])]
    return result, {"unique": len(order), "decoded": len(plain), "failed": len(failed),
                    "failed_fields": failed_fields}


def decode_fields_sample(doc: dict, servers: int = 3, networks: int = 3) -> dict:
    """Decode the protected fields of a small sample (top fields + the
    first N servers/networks) to prove the field envelopes open.
    Returns stats (counts only, never credential values)."""
    sample = {key: doc.get(key) for key in TOP_FIELDS if key in doc}
    sample["Servers"] = list(doc.get("Servers", []))[:servers]
    sample["Networks"] = list(doc.get("Networks", []))[:networks]
    _decoded, stats = decode_fields(sample)
    return stats


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


def decode(data: bytes | str, *, decode_fields_flag: bool = False, workers: int = 0,
           fields_partial: bool = False) -> dict:
    """Offline API: decrypt the complete catalog envelope and return the dict.
    Accepts the raw HTTP body (Base64 text, with or without the marker
    letter) or a local asset (configfile.json, FIELD_SECRET). By default
    the protected fields stay encoded; pass decode_fields_flag=True
    (requires argon2-cffi + PyCryptodome) to decode them too. With
    fields_partial=True the fields that fail keep their encoded form
    instead of aborting the whole document (see decode_fields)."""
    text = _text(data)
    if text.startswith("{"):
        doc = _catalog_json(text.encode("utf-8"))
    else:
        plain, _key = open_envelope_text(text)
        doc = _catalog_json(plain)
    if decode_fields_flag:
        doc, _stats = decode_fields(doc, workers=workers, strict=not fields_partial)
    return doc


def decode_with_key(data: bytes | str, *, decode_fields_flag: bool = False,
                    workers: int = 0, fields_partial: bool = False) -> tuple[dict, str, bool, dict | None]:
    """Like decode(), but also returns which key opened the envelope
    ("FILE"/"FIELD"/"plain"), whether the fields were decoded, and the
    field stats (or None when the fields were left encoded)."""
    text = _text(data)
    if text.startswith("{"):
        doc = _catalog_json(text.encode("utf-8"))
        key = "plain"
    else:
        plain, key = open_envelope_text(text)
        doc = _catalog_json(plain)
    stats = None
    fields_decoded = False
    if decode_fields_flag:
        doc, stats = decode_fields(doc, workers=workers, strict=not fields_partial)
        fields_decoded = True
    return doc, key, fields_decoded, stats


def run(file_bytes: bytes | str, *, decode_fields_flag: bool = False,
        workers: int = 0, fields_partial: bool = False) -> str | None:
    """Offline API: complete catalog JSON or None; never a partial list."""
    try:
        return json.dumps(decode(file_bytes, decode_fields_flag=decode_fields_flag,
                                 workers=workers, fields_partial=fields_partial),
                          ensure_ascii=False, indent=2, allow_nan=False) + "\n"
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
    parser.add_argument("--fields", action="store_true",
                        help="Decodificar también los campos protegidos (requiere argon2-cffi + PyCryptodome; falla cerrada si alguno no verifica)")
    parser.add_argument("--fields-partial", action="store_true",
                        help="Decodificar los campos que abran y dejar codificados los que fallen, reportándolos (para catálogos con campos no verificables)")
    parser.add_argument("--no-fields", action="store_true",
                        help="No decodificar los campos protegidos (por defecto)")
    parser.add_argument("--workers", type=int, default=0,
                        help="Procesos paralelos para --fields (0 = serie)")
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
            doc, key, _fd, _st = decode_with_key(_read(asset))
            assert key == "FIELD" and doc.get("Version") == "1.01", "self-test: el asset no abre como se esperaba"
            print(json.dumps({"self_test": "OK", "key": key, "version": doc.get("Version"),
                              "servers": len(doc.get("Servers", [])),
                              "networks": len(doc.get("Networks", []))}, ensure_ascii=False))
            if _FAST_CRYPTO:
                stats = decode_fields_sample(doc)
                print(json.dumps({"field_sample": "OK", **stats}, ensure_ascii=False))
            else:
                print(json.dumps({"field_sample": "SKIPPED",
                                  "reason": "FAST_CRYPTO_REQUIRED",
                                  "message": "Instala argon2-cffi + PyCryptodome para decodificar campos."},
                                 ensure_ascii=False))
            return 0
        if args.url is not None:
            raw = fetch_catalog(args.url)
        elif args.stdin:
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        elif args.file is not None:
            raw = _read(args.file)
        else:
            parser.error("se requiere un archivo, --url o --stdin (o --self-test)")
        want_fields = (args.fields or args.fields_partial) and not args.no_fields
        # --fields (estricto) tiene prioridad si se pasan los dos.
        partial = args.fields_partial and not args.fields
        doc, key, fields_decoded, stats = decode_with_key(
            raw, decode_fields_flag=want_fields, workers=args.workers,
            fields_partial=partial)
        rendered = json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        summary = {"key": key, "version": doc.get("Version"),
                   "servers": len(doc.get("Servers", [])),
                   "networks": len(doc.get("Networks", [])),
                   "fields_decoded": fields_decoded,
                   "field_envelopes": (stats or {}).get("unique") if stats else None}
        if stats:
            summary["fields_failed"] = stats.get("failed")
            if stats.get("failed_fields"):
                summary["failed_fields"] = stats.get("failed_fields")
        print(json.dumps(summary, ensure_ascii=False), file=sys.stderr)
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
