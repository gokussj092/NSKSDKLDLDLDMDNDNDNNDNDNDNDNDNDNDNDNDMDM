#!/usr/bin/env python3
"""Hex Custom 10.6.4 (com.hex.custom.jotchuast): decodificador de archivos
de perfil .hexcm (contenedor HXS3).

Python 3.10+, solo biblioteca estandar: Argon2id (RFC 9106), AES-256-GCM y
XChaCha20-Poly1305 estan implementados en Python puro en este archivo
(verificados contra argon2-cffi / PyCryptodome y contra la propia libreria
nativa de la app, libhexvpn.so, emulada con Unicorn). Con argon2-cffi +
PyCryptodome instalados el descifrado tarda ~0,3 s; en stdlib puro el
Argon2id con m=65536 KiB tarda varios minutos (se avisa por stderr).
Package com.hex.custom.jotchuast, versionCode 104, versionName 10.6.4.

Formato .hexcm (contenedor HXS3, nuevo en 10.6.4; el repo solo cubria
10.6.1, que era solo analisis, y Hex Tunnel 1.7.3, que usaba otro
formato). La app lo importa por el filtro VIEW de .*\\.hex y lo
exporta como <nombre>.hexcm. Estructura:

    [0:4]   magic "HXS3"
    [4]     version = 3
    [5]     flags: bit 0 = 1 -> protegido con contrasena (Argon2id)
    [6:22]  salt (16 B, aleatoria)
    [22:46] nonce24 (24 B, aleatoria)  -> capa interna XChaCha20-Poly1305
    [46:58] nonce12 (12 B, aleatoria)  -> capa externa AES-256-GCM
    [58:-16] ciphertext (capa externa)
    [-16:]  tag GCM (16 B)

    AAD de AMBAS capas = los 58 primeros bytes del archivo (cabecera).

Derivacion de claves (password = la contrasena del archivo, UTF-8):

    argon2_key = Argon2id(password, salt, t=3, m=65536 KiB, p=1,
                          version=0x13, salida 32 B)
    CONSTANTS32 = 265943050e89ae3aa403ae988c62026ef378c66a9c69be529929d7d5d3d47f3d
                  (constante fija de la app, libhexvpn.so .data.rel.ro)
    H1      = HMAC-SHA256(key=salt, msg=CONSTANTS32 || argon2_key)
    K_outer = HMAC-SHA256(key=H1, msg=b"HexVPN-server-v3-outer"
                          + b"com.hex.custom.jotchuast" + b"\\x01")
    K_inner = HMAC-SHA256(key=H1, msg=b"HexVPN-server-v3-inner"
                          + b"com.hex.custom.jotchuast" + b"\\x01")

Descifrado (dos capas):

    intermedio = AES-256-GCM(K_outer, nonce12, ct, tag, AAD=cabecera)
    plaintext  = XChaCha20-Poly1305(K_inner, nonce24,
                                    ct=intermedio[:-16], tag=intermedio[-16:],
                                    AAD=cabecera)

El plaintext es el perfil en JSON: {"version": 1, "server": {...},
"meta": {...}, "signature": "<64 hex>"}. El campo "signature" es un
SHA-256 de 64 hex cuya formula exacta NO se pudo determinar con la unica
muestra disponible (se probaron SHA-256/HMAC del JSON sin signature, con
la contrasena y con las claves de sesion); NO hace falta para abrir el
archivo (las etiquetas AEAD ya lo autentican) y este script lo conserva
tal cual al re-serializar. Al sellar un perfil modificado se pone
signature = SHA-256 del JSON sin el campo signature y se advierte que
la formula de firma esta sin verificar: la app podria rechazar el
archivo al importarlo si valida la firma.

Sin contrasena (flags bit 0 = 0) la app usa otra rama (constantes
.data.rel.ro + la misma funcion MIX, sin Argon2id); no existe ninguna
muestra .hexcm sin contrasena, asi que esa rama NO esta implementada:
este script devuelve UNSUPPORTED_FLAGS en ese caso.

La app NO define un esquema URI propio de texto (el manifest solo
declara el filtro VIEW de .*\\.hex y application/octet-stream); no hay
hexcustom://. La nube es Firebase Firestore (FileRepository, IDs
"hexcustom" + 10 letras), no un catalogo HTTP.

ESTADO DE VERIFICACION: el archivo real NONE_BREAKER__0_0osx.hexcm
(7.054 B, SHA-256 7babe831...) ABRE con la contrasena "None_breaker"
(tag GCM autentico, tag Poly1305 autentico, JSON valido): perfil
"NONE_BREAKER" (usuario Nonbreaker, contrasena 224012, slipstream
dsl.depwise.store, empresa Ethio telecom, pais et, bloqueado=true,
expira 1794700800000). La criptografia en Python puro reproduce byte a
byte la de la libreria nativa emulada. El round-trip sellar -> abrir es
exacto. Lo que FALTA es la confirmacion de extremo a extremo con un
segundo .hexcm (por ejemplo sin contrasena, o sellado por la app) y la
formula de la firma. Los archivos .sks estan EXCLUIDOS por indicacion
de Pedro y no se implementan aqui (esta app tampoco los usa).

Uso:
    python3 Hex_Custom_archivos.py archivo.hexcm --password <pass>
    python3 Hex_Custom_archivos.py archivo.hexcm --password <pass> --summary
    python3 Hex_Custom_archivos.py --seal perfil.json --password <pass> -o out.hexcm
    python3 Hex_Custom_archivos.py --self-test
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac as _hmac
import json
import os
import struct
import sys
from pathlib import Path

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1

PACKAGE = b"com.hex.custom.jotchuast"
LABEL_OUTER = b"HexVPN-server-v3-outer"
LABEL_INNER = b"HexVPN-server-v3-inner"
# Constante fija de 32 bytes de libhexvpn.so (.data.rel.ro, 0x1b290+0x1b340).
CONSTANTS32 = bytes.fromhex(
    "265943050e89ae3aa403ae988c62026ef378c66a9c69be529929d7d5d3d47f3d")
ARGON_TIME = 3
ARGON_MEMORY_KIB = 65536
ARGON_PARALLELISM = 1
ARGON_VERSION = 0x13
MAX_BYTES = 64 * 1024 * 1024

# ---- rutas rapidas opcionales (argon2-cffi + PyCryptodome) ----
try:
    from argon2.low_level import Type as _Argon2Type, hash_secret_raw as _argon2_fast
    _HAVE_ARGON2 = True
except Exception:  # pragma: no cover - dependencia opcional
    _HAVE_ARGON2 = False
try:
    from Crypto.Cipher import AES as _AES, ChaCha20_Poly1305 as _XChaCha
    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover - dependencia opcional
    _HAVE_CRYPTO = False


class DecodeError(ValueError):
    """Error de decodificacion con codigo estable para la CLI y SP-DECODE."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _text(data: bytes | str) -> str:
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="strict")
    return data


def _json(data: bytes | str):
    try:
        doc = json.loads(_text(data))
    except (ValueError, UnicodeDecodeError) as exc:
        raise DecodeError("INVALID_JSON", "JSON invalido o con claves duplicadas.") from exc
    if not isinstance(doc, dict):
        raise DecodeError("WRONG_DOCUMENT", "El documento debe contener un objeto JSON.")
    return _validate(doc)


def _validate(doc: dict) -> dict:
    if doc.get("version") != 1:
        raise DecodeError("WRONG_DOCUMENT", "El perfil debe tener version == 1.")
    server = doc.get("server")
    if not isinstance(server, dict) or not server:
        raise DecodeError("WRONG_DOCUMENT", "El perfil debe tener un objeto server no vacio.")
    if "meta" in doc and not isinstance(doc["meta"], dict):
        raise DecodeError("WRONG_DOCUMENT", "El campo meta debe ser un objeto.")
    return doc


def _argon2id_fast(password: bytes, salt: bytes) -> bytes:
    return _argon2_fast(password, salt, time_cost=ARGON_TIME,
                        memory_cost=ARGON_MEMORY_KIB,
                        parallelism=ARGON_PARALLELISM, hash_len=32,
                        type=_Argon2Type.ID, version=ARGON_VERSION)


def _derive_keys(password: bytes, salt: bytes):
    """Argon2id -> H1 -> (K_outer, K_inner). Devuelve (K_outer, K_inner)."""
    if _HAVE_ARGON2:
        argon_key = _argon2id_fast(password, salt)
    else:
        print("Aviso: argon2-cffi no disponible; Argon2id en Python puro "
              "(m=65536 KiB) puede tardar varios minutos.", file=sys.stderr)
        argon_key = _argon2id(password, salt, time_cost=ARGON_TIME,
                              memory_kib=ARGON_MEMORY_KIB,
                              parallelism=ARGON_PARALLELISM, tag_len=32)
    h1 = _hmac.new(salt, CONSTANTS32 + argon_key, hashlib.sha256).digest()
    k_outer = _hmac.new(h1, LABEL_OUTER + PACKAGE + b"\x01", hashlib.sha256).digest()
    k_inner = _hmac.new(h1, LABEL_INNER + PACKAGE + b"\x01", hashlib.sha256).digest()
    return k_outer, k_inner

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


# ------------------------------------------- ChaCha20 / Poly1305 / XChaCha20
def _rotl32(v, n):
    return ((v << n) | (v >> (32 - n))) & MASK32


def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & MASK32; s[d] ^= s[a]; s[d] = _rotl32(s[d], 16)
    s[c] = (s[c] + s[d]) & MASK32; s[b] ^= s[c]; s[b] = _rotl32(s[b], 12)
    s[a] = (s[a] + s[b]) & MASK32; s[d] ^= s[a]; s[d] = _rotl32(s[d], 8)
    s[c] = (s[c] + s[d]) & MASK32; s[b] ^= s[c]; s[b] = _rotl32(s[b], 7)


def _chacha20_block(key, counter, nonce12):
    """Un bloque ChaCha20 de 64 bytes (RFC 8439 2.3)."""
    const = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)
    k = struct.unpack("<8I", key)
    n = struct.unpack("<3I", nonce12)
    st = list(const) + list(k) + [counter] + list(n)
    x = st[:]
    for _ in range(10):
        _qr(x, 0, 4, 8, 12); _qr(x, 1, 5, 9, 13); _qr(x, 2, 6, 10, 14); _qr(x, 3, 7, 11, 15)
        _qr(x, 0, 5, 10, 15); _qr(x, 1, 6, 11, 12); _qr(x, 2, 7, 8, 13); _qr(x, 3, 4, 9, 14)
    return struct.pack("<16I", *[ (a + b) & MASK32 for a, b in zip(x, st)])


def _hchacha20(key, nonce16):
    """HChaCha20 (RFC 8439 2.2): subclave de 32 bytes a partir de un nonce de 16 bytes."""
    const = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)
    k = struct.unpack("<8I", key)
    n = struct.unpack("<4I", nonce16)
    x = list(const) + list(k) + list(n)
    for _ in range(10):
        _qr(x, 0, 4, 8, 12); _qr(x, 1, 5, 9, 13); _qr(x, 2, 6, 10, 14); _qr(x, 3, 7, 11, 15)
        _qr(x, 0, 5, 10, 15); _qr(x, 1, 6, 11, 12); _qr(x, 2, 7, 8, 13); _qr(x, 3, 4, 9, 14)
    return struct.pack("<8I", *(x[0:4] + x[12:16]))


def _chacha20_xor(key, nonce12, data, counter=1):
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = _chacha20_block(key, counter, nonce12)
        counter += 1
        chunk = data[i:i + 64]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
    return bytes(out)


def _poly1305_mac(key32, msg):
    """Poly1305 (RFC 8439 2.5.2). key32 = r(16) || s(16)."""
    r = int.from_bytes(key32[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key32[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        n = int.from_bytes(block + b"\x01", "little")
        acc = ((acc + n) * r) % p
    return ((acc + s) % (1 << 128)).to_bytes(16, "little")


def _xchacha20_poly1305_decrypt(key, nonce24, ciphertext, tag, aad=b""):
    """XChaCha20-Poly1305 (RFC 8439 2.8). nonce24: 24 bytes. Lanza ValueError si el tag no verifica."""
    if _HAVE_CRYPTO:
        c = _XChaCha.new(key=key, nonce=nonce24)
        if aad:
            c.update(aad)
        return c.decrypt_and_verify(ciphertext, tag)
    subkey = _hchacha20(key, nonce24[:16])
    nonce12 = b"\x00\x00\x00\x00" + nonce24[16:24]
    poly_key = _chacha20_block(subkey, 0, nonce12)[:32]
    pt = _chacha20_xor(subkey, nonce12, ciphertext, counter=1)

    def pad16(d):
        return d + b"\x00" * ((-len(d)) % 16)
    mac_data = pad16(aad) + pad16(ciphertext) + struct.pack("<QQ", len(aad), len(ciphertext))
    calc = _poly1305_mac(poly_key, mac_data)
    if calc != tag:
        raise ValueError("Poly1305 tag mismatch")
    return pt


def _xchacha20_poly1305_encrypt(key, nonce24, plaintext, aad=b""):
    """XChaCha20-Poly1305: devuelve (ciphertext, tag)."""
    if _HAVE_CRYPTO:
        c = _XChaCha.new(key=key, nonce=nonce24)
        if aad:
            c.update(aad)
        ct, tag = c.encrypt_and_digest(plaintext)
        return ct, tag
    subkey = _hchacha20(key, nonce24[:16])
    nonce12 = b"\x00\x00\x00\x00" + nonce24[16:24]
    poly_key = _chacha20_block(subkey, 0, nonce12)[:32]
    ct = _chacha20_xor(subkey, nonce12, plaintext, counter=1)

    def pad16(d):
        return d + b"\x00" * ((-len(d)) % 16)
    mac_data = pad16(aad) + pad16(ct) + struct.pack("<QQ", len(aad), len(ct))
    return ct, _poly1305_mac(poly_key, mac_data)


def _aes_gcm_decrypt_fast(key, nonce, ciphertext, tag, aad=b""):
    if _HAVE_CRYPTO:
        c = _AES.new(key, _AES.MODE_GCM, nonce=nonce)
        if aad:
            c.update(aad)
        return c.decrypt_and_verify(ciphertext, tag)
    return _aes_gcm_decrypt(key, nonce, ciphertext, tag, aad=aad)


def _aes_gcm_encrypt_fast(key, nonce, plaintext, aad=b""):
    if _HAVE_CRYPTO:
        c = _AES.new(key, _AES.MODE_GCM, nonce=nonce)
        if aad:
            c.update(aad)
        ct, tag = c.encrypt_and_digest(plaintext)
        return ct, tag
    return _aes_gcm_encrypt(key, nonce, plaintext, aad=aad)


# ------------------------------------------------------------------ formato
def parse_container(data: bytes) -> dict:
    """Valida la cabecera HXS3 y devuelve sus campos. Lanza DecodeError."""
    if len(data) < 58 + 16:
        raise DecodeError("SIZE", "El archivo es demasiado corto para un .hexcm HXS3.")
    if data[:4] != b"HXS3":
        raise DecodeError("NOT_HXS3", "El archivo no empieza por el magic HXS3.")
    version = data[4]
    if version != 3:
        raise DecodeError("UNSUPPORTED_VERSION", f"Version de contenedor {version}, solo se soporta 3.")
    flags = data[5]
    return {
        "version": version,
        "flags": flags,
        "password_protected": bool(flags & 0x01),
        "salt": data[6:22],
        "nonce24": data[22:46],
        "nonce12": data[46:58],
        "header": data[:58],
        "ciphertext": data[58:-16],
        "tag": data[-16:],
    }


def decrypt_bytes(data: bytes, password: bytes | str | None = None) -> bytes:
    """Abre un .hexcm HXS3 y devuelve el JSON del perfil (bytes)."""
    hdr = parse_container(data)
    if not hdr["password_protected"]:
        raise DecodeError("UNSUPPORTED_FLAGS",
                          "Archivo sin contrasena (flags bit 0 = 0): esa rama no "
                          "esta implementada; no existe ninguna muestra para verificarla.")
    if password is None:
        raise DecodeError("PASSWORD_REQUIRED",
                          "Este .hexcm esta protegido con contrasena; pasa --password.")
    if isinstance(password, str):
        password = password.encode("utf-8")
    k_outer, k_inner = _derive_keys(password, hdr["salt"])
    try:
        inter = _aes_gcm_decrypt_fast(k_outer, hdr["nonce12"], hdr["ciphertext"],
                                      hdr["tag"], aad=hdr["header"])
    except ValueError as exc:
        raise DecodeError("WRONG_PASSWORD",
                          "La contrasena no abre el archivo (tag GCM no verifica).") from exc
    if len(inter) < 16:
        raise DecodeError("DECRYPT_FAILED", "La capa interna es demasiado corta.")
    try:
        pt = _xchacha20_poly1305_decrypt(k_inner, hdr["nonce24"], inter[:-16],
                                         inter[-16:], aad=hdr["header"])
    except ValueError as exc:
        raise DecodeError("DECRYPT_FAILED",
                          "La capa interna no verifica (tag Poly1305).") from exc
    return pt


def decode(data: bytes | str, password: bytes | str | None = None) -> dict:
    """decode() de SP-DECODE: bytes/str del .hexcm -> dict del perfil."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return _json(decrypt_bytes(data, password=password))


def seal(profile: dict | bytes, password: bytes | str,
         salt: bytes | None = None, nonce24: bytes | None = None,
         nonce12: bytes | None = None) -> bytes:
    """Crea un .hexcm HXS3 a partir de un perfil (dict o JSON bytes).

    La firma se conserva si el dict ya trae "signature"; si no, se pone
    signature = SHA-256 del JSON sin el campo signature (formula sin
    verificar: ver la cabecera del modulo).
    """
    if isinstance(profile, dict):
        doc = dict(profile)
        if "signature" not in doc:
            unsigned = {k: v for k, v in doc.items() if k != "signature"}
            raw_u = json.dumps(unsigned, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            doc["signature"] = hashlib.sha256(raw_u).hexdigest()
        raw = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    else:
        raw = profile if isinstance(profile, bytes) else profile.encode("utf-8")
    if isinstance(password, str):
        password = password.encode("utf-8")
    salt = salt if salt is not None else os.urandom(16)
    nonce24 = nonce24 if nonce24 is not None else os.urandom(24)
    nonce12 = nonce12 if nonce12 is not None else os.urandom(12)
    header = b"HXS3" + bytes([3, 0x01]) + salt + nonce24 + nonce12
    k_outer, k_inner = _derive_keys(password, salt)
    inner_ct, inner_tag = _xchacha20_poly1305_encrypt(k_inner, nonce24, raw, aad=header)
    inter = inner_ct + inner_tag
    ct, tag = _aes_gcm_encrypt_fast(k_outer, nonce12, inter, aad=header)
    return header + ct + tag


def summary(doc: dict) -> dict:
    """Resumen corto del perfil (sin valores sensibles completos)."""
    server = doc.get("server", {}) if isinstance(doc.get("server"), dict) else {}
    meta = doc.get("meta", {}) if isinstance(doc.get("meta"), dict) else {}
    return {
        "version": doc.get("version"),
        "server_name": server.get("name"),
        "username": server.get("username"),
        "server_type": server.get("serverType"),
        "tunnel_type": server.get("tunnelType"),
        "slipstream_domain": server.get("slipstream_domain"),
        "company": meta.get("company"),
        "country": meta.get("countryIso"),
        "blocked": meta.get("blocked"),
        "expires_at_ms": meta.get("expiresAt"),
        "has_signature": bool(doc.get("signature")),
    }


# ---------------------------------------------------------------------- CLI
def _read_file(path: Path) -> bytes:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise DecodeError("IO_ERROR", f"No se pudo leer el archivo: {path}") from exc
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La entrada supera el limite de tamano.")
    return data


def _write_output(path: Path, data: bytes) -> None:
    if path.exists():
        raise DecodeError("IO_ERROR", f"El archivo de salida ya existe: {path}")
    path.write_bytes(data)


def _self_test() -> int:
    """Pruebas sinteticas; no usa archivos reales ni red.

    1. Vector RFC 9106 Argon2id. 2. Vector NIST AES-256-GCM.
    3. Vector XChaCha20-Poly1305 de respuesta conocida (verificado contra
    PyCryptodome). 4. Round-trip sellar->abrir con contrasena de prueba.
    5. Tag GCM alterado rechazado. 6. Tag Poly1305 alterado rechazado.
    7. Flags sin contrasena rechazados.
    """
    cases = []

    def check(name, ok):
        cases.append(bool(ok))
        print(f"  [{'OK' if ok else 'FAIL'}] {name}")

    print("Hex_Custom self-test:")
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
    try:
        xkey = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        xnonce = bytes.fromhex("07000000404142434445464748494a4b0000000000000000")
        xpt = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
               b"only one tip for the future, sunscreen would be it.")
        xaad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        xct = bytes.fromhex("453c0693a7407f04ff4c56aedb17a3c0a1afff01174930fc22287c33dbcf0ac8b89ad929530a1bb3ab5e69f24c7f6070c8f840c9abb4f69fbfc8a7ff5126faeebbb55805ee9c1cf2ce5a57263287aec5780f04ec324c3514122cfc3231fc1a8b718a62863730a2702bb76366116bed09e0fd")
        xtag = bytes.fromhex("5c6d84b6b0c1abaf249d5dd0f7f5a7ea")
        out = _xchacha20_poly1305_decrypt(xkey, xnonce, xct, xtag, aad=xaad)
        check("XChaCha20-Poly1305 known-answer", out == xpt)
    except ValueError:
        check("XChaCha20-Poly1305 known-answer", False)
    doc = {"version": 1,
           "server": {"name": "TEST", "username": "u", "password": "p",
                      "serverType": 12, "tunnelType": -1},
           "meta": {"blocked": False, "company": "Test", "countryIso": "mx"}}
    salt = bytes(range(16))
    n24 = bytes(range(16, 40))
    n12 = bytes(range(40, 52))
    try:
        blob = seal(doc, b"test-password", salt=salt, nonce24=n24, nonce12=n12)
        got = decode(blob, password=b"test-password")
        check("round-trip sellar -> abrir", got.get("server", {}).get("name") == "TEST"
              and got.get("meta", {}).get("company") == "Test")
    except DecodeError:
        check("round-trip sellar -> abrir", False)
    try:
        bad = bytearray(seal(doc, b"test-password", salt=salt, nonce24=n24, nonce12=n12))
        bad[-1] ^= 0x01
        decode(bytes(bad), password=b"test-password")
        check("tag GCM alterado rechazado", False)
    except DecodeError as exc:
        check("tag GCM alterado rechazado", exc.code in ("WRONG_PASSWORD", "DECRYPT_FAILED"))
    try:
        # Alterar el tag Poly1305 INTERNO: abrir la capa externa, tocar
        # inter[-1], volver a cifrar la capa externa y decodificar.
        blob0 = seal(doc, b"test-password", salt=salt, nonce24=n24, nonce12=n12)
        hdr0 = parse_container(blob0)
        k_o, k_i = _derive_keys(b"test-password", hdr0["salt"])
        inter0 = _aes_gcm_decrypt_fast(k_o, hdr0["nonce12"], hdr0["ciphertext"],
                                       hdr0["tag"], aad=hdr0["header"])
        bad_inter = bytearray(inter0)
        bad_inter[-1] ^= 0x01
        ct0, tag0 = _aes_gcm_encrypt_fast(k_o, hdr0["nonce12"], bytes(bad_inter),
                                          aad=hdr0["header"])
        decode(hdr0["header"] + ct0 + tag0, password=b"test-password")
        check("tag Poly1305 alterado rechazado", False)
    except DecodeError as exc:
        check("tag Poly1305 alterado rechazado", exc.code == "DECRYPT_FAILED")
    try:
        hdr = b"HXS3" + bytes([3, 0x00]) + bytes(52) + bytes(32)
        decode(hdr, password=b"x")
        check("flags sin contrasena rechazados", False)
    except DecodeError as exc:
        check("flags sin contrasena rechazados", exc.code == "UNSUPPORTED_FLAGS")
    passed = sum(cases)
    print(json.dumps({"self_test": "pass" if passed == len(cases) else "fail",
                      "passed": passed, "total": len(cases)}, ensure_ascii=False))
    return 0 if passed == len(cases) else 1


def run(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path, help="Archivo .hexcm")
    source.add_argument("--stdin", action="store_true", help="Lee el .hexcm desde stdin")
    source.add_argument("--self-test", action="store_true",
                        help="Pruebas sinteticas; no usa archivos reales ni red")
    source.add_argument("--seal", type=Path, metavar="JSON",
                        help="Crea un .hexcm a partir de un perfil JSON (requiere --password y -o)")
    parser.add_argument("--password", help="Contrasena del archivo .hexcm")
    parser.add_argument("-o", "--output", type=Path, help="Guardar salida; no sobrescribe")
    parser.add_argument("--summary", action="store_true",
                        help="Solo resumen del perfil, sin el JSON completo")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    try:
        if args.seal is not None:
            if args.password is None or args.output is None:
                print(json.dumps({"error": "ARGS",
                                  "message": "--seal requiere --password y -o."},
                                 ensure_ascii=False), file=sys.stderr)
                return 2
            profile = json.loads(args.seal.read_text(encoding="utf-8"))
            blob = seal(profile, args.password)
            _write_output(args.output, blob)
            print(json.dumps({"sealed": str(args.output), "bytes": len(blob)},
                             ensure_ascii=False))
            return 0
        if args.stdin:
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise DecodeError("SIZE_LIMIT", "La entrada supera el limite de tamano.")
        else:
            raw = _read_file(args.file)
        doc = decode(raw, password=args.password)
        rendered = json.dumps(summary(doc) if args.summary else doc,
                              ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            _write_output(args.output, rendered.encode("utf-8"))
        else:
            sys.stdout.write(rendered)
        return 0
    except DecodeError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}, ensure_ascii=False),
              file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR", "message": "No se pudo leer o escribir el archivo."},
                         ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(run())
