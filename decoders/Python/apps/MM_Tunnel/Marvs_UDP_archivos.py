#!/usr/bin/env python3
"""MM Tunnel (Marvs UDP) v1.11.06.1: decodificador de archivos de perfil .mmt.

Python 3.10+, solo biblioteca estandar: Argon2id (RFC 9106) y AES-256-GCM
estan implementados en Python puro en este archivo (verificados contra
argon2-cffi y PyCryptodome). Un descifrado tarda ~90 s en stdlib puro;
~0,3 s con argon2-cffi + PyCryptodome.
Package co.strongteam.marvsudp, versionCode 48, versionName v1.11.06.1.

Formato .mmt (importacion declarada en el manifest:
application/x-mmt, application/octet-stream, pathPattern .*\\.mmt,
activity com.v2ray.ang.ui.ConfigFileParser). Al importar, la app lee el
archivo como texto y llama Libv2ray.parseConfig() (el Go Encrypt/decrypt
de libgojni.so); si parseConfig falla, lo intenta como JSON plano
(Hometab.Companion.a()). Al EXPORTAR/compartir un perfil, la app hace
Gson.toJson(NetworkList) y lo cifra con Libv2ray.encrypt() (el Go
Encrypt(), clave FILE_SECRET), inserta una letra ASCII aleatoria en el
indice 3 del Base64, y lo guarda como <nombre>.mmt (NetworkAdapter).
Es decir: el .mmt que produce la app usa FILE_SECRET con la letra
marcadora, y la ruta de importacion tiene ademas el fallback
FIELD_SECRET (DO()/do_()). Este script prueba en orden: sobre
FILE_SECRET sin la marcadora, sobre FILE_SECRET tal cual y sobre
FIELD_SECRET tal cual, y reporta cual abrio el sobre:

    Base64( salt[16] || nonce[12] || AES-256-GCM(key, nonce, AAD=salt) )
    key = Argon2id(password, salt, time=3, memory=16384 KiB, threads=1, 32 B)
    FILE_SECRET = "iOi/hqT/TocUv0UbDImfWPGR1mfSdzzX" (Encrypt/decrypt, .rodata 0x365e74)
    FIELD_SECRET = "NewDecryptLibPassword" (EO/DO, .rodata 0x353439 + "Password")

FILE_SECRET y FIELD_SECRET son constantes de formato de la app, no
credenciales de cuenta. El texto descifrado es el perfil en JSON (el
JSON Gson de un NetworkList: Name, TunnelType, Payload, SNI,
V2rayConfig, etc.) o, para el asset, el JSON completo del catalogo
(mismo esquema Servers/Networks). Las protecciones (contrasena, HWID,
bloqueo de red) viven DENTRO del JSON descifrado y se verifican despues
del descifrado, no forman parte de la derivacion de la clave.

La app NO define un esquema URI propio de texto: el manifest solo
declara v2rayng://install-config y v2rayng://install-sub (genericos de
v2rayNG, no de MM Tunnel), asi que este script no incluye ningun
esquema URI.

ESTADO DE VERIFICACION: el sobre esta VERIFICADO contra la propia
libreria de la app: assets/configfile.json (el mismo sobre,
FIELD_SECRET, sin marcadora) abre (tag GCM autentico, JSON valido,
Version "1.01", 34 Servers, 555 Networks), el catalogo en vivo
(POST https://strongteam.co/api/mmtunnel/) abre con FILE_SECRET sin la
marcadora (Version "2.71", 37 Servers, 818 Networks), el round-trip
cifrar/descifrar es exacto con AMBAS claves (FILE con marcadora y
FIELD sin ella), y la criptografia en Python puro reproduce byte a byte
la de argon2-cffi / PyCryptodome. Lo que FALTA es la confirmacion de
extremo a extremo con un archivo .mmt real exportado por la app en un
telefono (no existe ninguna muestra .mmt en este analisis); si un .mmt
real no abre con este script, el bloqueador es que el archivo no usa
este sobre o usa otra clave, y habria que contrastarlo con ese archivo
concreto. Los archivos .sks estan EXCLUIDOS por indicacion de Pedro y
no se implementan aqui (esta app tampoco los usa).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import struct
import json
import math
from pathlib import Path
import re
import sys

MAX_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1

# Argon2id parameters, fixed in the Go core (DO/Encrypt).
ARGON_TIME = 3
ARGON_MEMORY_KIB = 16384
ARGON_THREADS = 1
ARGON_KEY_LEN = 32
# FILE_SECRET: the .mmt/export key (Encrypt()/decrypt()), libgojni.so .rodata 0x365e74.
# FIELD_SECRET: the import fallback key (DO()/do_()); the bundled asset
# configfile.json opens with FIELD_SECRET. The envelope is identical.
# App format constants, not account credentials.
FILE_SECRET = b"iOi/hqT/TocUv0UbDImfWPGR1mfSdzzX"
FIELD_SECRET = b"NewDecryptLibPassword"

# Fast path (argon2-cffi + PyCryptodome): ~0.3 s per envelope instead of
# ~88 s with the pure stdlib Argon2id below. Optional; the script stays
# correct without it.
try:
    from argon2.low_level import Type as _Argon2Type, hash_secret_raw as _argon2_fast
    from Crypto.Cipher import AES as _AES_FAST
    _FAST_CRYPTO = True
except Exception:  # pragma: no cover - optional dependency
    _FAST_CRYPTO = False



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


def _envelope_attempts(text: str) -> list[tuple[bytes, bytes, str]]:
    """Candidate (blob, password, key name) attempts, cheapest-first.
    The app's Encrypt() inserts one random ASCII letter at Base64 index 3
    AFTER encoding, so an exported .mmt has length 1 (mod 4); the bundled
    asset and a plain FIELD envelope have length 0 (mod 4) and no marker."""
    compact = re.sub(r"[ \t\r\n]", "", text)

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
        raise DecodeError("FORMAT_ERROR", "Se esperaba Base64 estándar del archivo .mmt.")
    return attempts


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
    otherwise pure stdlib (~90 s at m=16384)."""
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


def decode(data: bytes | str) -> dict:
    """Offline API: decrypt a .mmt file (Base64 envelope) and return the dict.
    Also accepts a plain JSON profile (the app's ConfigFileParser fallback)
    and the bundled asset configfile.json (catalog-shaped, FIELD_SECRET)."""
    doc, _key = decode_with_key(data)
    return doc


def decode_with_key(data: bytes | str) -> tuple[dict, str]:
    """Like decode(), but also returns which key opened the envelope
    ("FILE" for an exported .mmt, "FIELD" for the import fallback /
    bundled asset, "plain" for a JSON profile)."""
    text = _text(data)
    if text.startswith("{"):
        return _json(text.encode("utf-8")), "plain"
    last_error: DecodeError | None = None
    for blob, password, name in _envelope_attempts(text):
        try:
            plain = decrypt_envelope(blob, password)
            return _json(plain), name
        except DecodeError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise DecodeError("DECRYPT_FAILED", "No se pudo descifrar el archivo .mmt.")


def run(file_bytes: bytes | str) -> str | None:
    """Offline API: complete profile JSON or None; never a partial document."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


def _read(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", type=Path, help="Archivo .mmt (también acepta configfile.json o un perfil JSON plano)")
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
            # Synthetic round-trips: a NetworkList profile JSON, encrypted
            # exactly as the app's export does (Encrypt/FILE + marker
            # letter) and as the import fallback does (DO/FIELD, no
            # marker); decode() must open both and report the right key.
            import os as _os
            import random as _random
            import string as _string
            profile = {"Name": "Test", "TunnelType": "SSH",
                       "Payload": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                       "SNI": "example.com"}
            plain = json.dumps(profile, ensure_ascii=False).encode("utf-8")
            blob_file = _encrypt_blob(plain, FILE_SECRET, _os.urandom(16), _os.urandom(12))
            letter = _random.choice(_string.ascii_letters)
            exported = blob_file[:3] + letter + blob_file[3:]
            _doc, _k = decode_with_key(exported)
            assert _k == "FILE" and _doc == profile, "round-trip FILE con marcadora failed"
            print(json.dumps({"round_trip": "OK", "key": _k, "marker": True}, ensure_ascii=False))
            blob_field = _encrypt_blob(plain, FIELD_SECRET, _os.urandom(16), _os.urandom(12))
            _doc, _k = decode_with_key(blob_field)
            assert _k == "FIELD" and _doc == profile, "round-trip FIELD failed"
            print(json.dumps({"round_trip": "OK", "key": _k, "marker": False}, ensure_ascii=False))
            return 0
        if args.file is None:
            parser.error("se requiere un archivo .mmt (o --self-test)")
        doc, key = decode_with_key(_read(args.file))
        rendered = json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        print(json.dumps({"key": key,
                          "top_keys": sorted(doc.keys())},
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
