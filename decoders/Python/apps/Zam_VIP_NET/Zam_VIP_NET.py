#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zam VIP NET / Free VIP Net — decodificador de catalogo para SP-DECODE.
=====================================================================
App:        zam.freevipnet.com 42.0 (build 42), familia RENZ
            (renz.javacodez.vpn.*), XAPK APKPure variante arm64-v8a.
Catalogo:   GET https://www.zamscript.xyz/api/json/l160D7cKZ9XXUQTJMjnpZKNp5QvVBMEC0GRihMCQBr2mSPNBrkvWMv547qVefd5F
            (Volley StringRequest; la app lo pide solo si existe
            /META-INF/KEY0.RSA o /META-INF/BNDLTOOL.RSA en el APK).
            Respuesta: una sola linea Base64 (927.168 caracteres el
            2026-11-14). Version del catalogo: 2.458.
            113 servidores, 591 redes (networks), usuario/clave zambro1.

Esquema (libovpn3.so, RenzUtils.decrypt, 3 modos):
  Modo 0 (catalogo y la mayoria de campos):
      Base64 -> AES-128-CBC (key = SHA-256(seed)[:16], IV fijo)
             -> XXTEA (delta 0x85A92C1F, sumas negadas, ultima palabra
                = longitud del plaintext)
  Modo 1 (ServerIPHost, SNIHost, Payload, V2Ray.PATH/V2RayHost,
          CustomV2RAYConfig):
      Base64 -> Threefish-256 por bloques de 32 B
                (tweak = (n_bloque, 192*n_bloque), key = HKDF-SHA256
                de 32 B: salt = FIXED_SALT (32 B), IKM = seed, info = "")
             -> quitar NULs finales
             -> AES-128-CBC (key = HKDF-SHA256 de 16 B: salt =
                FIXED_SALT[:16], mismo IV)
  Modo 2 (Username / Password, caracteres invisibles):
      ZWSP(U+200B)=0 / ZWNJ(U+200C)=1 (ZWJ U+200D se ignora),
      8 tokens -> 1 byte, intercambio de bits adyacentes, XOR 0x5A
             -> XXTEA (key = PBKDF2-HMAC-SHA256(seed, FIXED_SALT,
                100000 iters)[:16])
             -> AES-256-CBC (key = PBKDF2 de 32 B,
                IV = primeros 16 B de la salida XXTEA)

Archivos propios (ver Zam_VIP_NET_archivos.py):
  .zvn  -> texto "zamvipnet://<cifrado modo 0>"  (ACTION_VIEW en el
           manifest; tambien esquema de enlace de texto)
  .js / .rj -> texto con el cifrado modo 0 directamente.

Solo stdlib. Uso:
  python3 Zam_VIP_NET.py [--url URL] [--out JSON] [--raw-out JSON]
  python3 Zam_VIP_NET.py --self-test
"""
import base64
import hashlib
import hmac
import json
import struct
import sys
import urllib.request

CATALOG_URL = ("https://www.zamscript.xyz/api/json/"
               "l160D7cKZ9XXUQTJMjnpZKNp5QvVBMEC0GRihMCQBr2mSPNBrkvWMv547qVefd5F")
# User-Agent que usa la app (Volley sobre Android 14, Redmi 14C). El
# cuerpo devuelto es identico con este UA y con el de curl.
USER_AGENT = ("Dalvik/2.1.0 (Linux; U; Android 14; Redmi 14C "
              "Build/UP1A.231005.007)")

# Material criptografico extraido de libovpn3.so (.rodata):
SEED = bytes.fromhex("ecd4f3ceaf62556b0f4f9c43207511249c4bdc59b68ac9ab9d7b490428e88fde")
FIXED_SALT = bytes.fromhex("be432e5a50952a899b29b7c23162fe70defca1061c9fa7927c65c3f6ebe9f77e")
IV = bytes.fromhex("b329f9d1ab699b9ad1aa9c4ce918d4f8")  # IV modo 0 y modo 1
AES_KEY = hashlib.sha256(SEED).digest()[:16]         # key modo 0
PBKDF2_KEY = hashlib.pbkdf2_hmac("sha256", SEED, FIXED_SALT, 100000, 32)

_M32 = 0xFFFFFFFF
_M64 = (1 << 64) - 1

# --------------------------------------------------------------------------
# AES-128 (FIPS-197, implementacion pura en stdlib)


def _gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _make_sbox():
    sbox = [0] * 256
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        xformed = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) \
            ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        xformed = (xformed ^ 0x63) & 0xFF
        sbox[p] = xformed
        if p == 1:
            break
    sbox[0] = 0x63  # el generador no toca p=0; 0x63 es el valor FIPS-197
    return sbox


_SBOX = _make_sbox()
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _aes_key_expand(key):
    """AES-128 key expansion -> 44 palabras de 32 bits."""
    w = list(struct.unpack(">4I", key))
    for i in range(4, 44):
        temp = w[i - 1]
        if i % 4 == 0:
            rot = ((temp << 8) | (temp >> 24)) & _M32
            sub = (_SBOX[(rot >> 24) & 0xFF] << 24) | (_SBOX[(rot >> 16) & 0xFF] << 16) \
                | (_SBOX[(rot >> 8) & 0xFF] << 8) | _SBOX[rot & 0xFF]
            temp = sub ^ (_RCON[i // 4 - 1] << 24)
        w.append((w[i - 4] ^ temp) & _M32)
    return w


def _aes_encrypt_block(rk, block):
    s = bytearray(block)
    for c in range(4):
        for r in range(4):
            s[4 * c + r] ^= (rk[c] >> (24 - 8 * r)) & 0xFF
    for rnd in range(1, 10):
        # SubBytes + ShiftRows
        t = bytearray(16)
        for r in range(4):
            for c in range(4):
                t[4 * c + r] = _SBOX[s[4 * ((c + r) % 4) + r]]
        s = t
        # MixColumns
        t = bytearray(16)
        for c in range(4):
            a0, a1, a2, a3 = s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]
            t[4 * c] = _gf_mul(a0, 2) ^ _gf_mul(a1, 3) ^ a2 ^ a3
            t[4 * c + 1] = a0 ^ _gf_mul(a1, 2) ^ _gf_mul(a2, 3) ^ a3
            t[4 * c + 2] = a0 ^ a1 ^ _gf_mul(a2, 2) ^ _gf_mul(a3, 3)
            t[4 * c + 3] = _gf_mul(a0, 3) ^ a1 ^ a2 ^ _gf_mul(a3, 2)
        s = t
        # AddRoundKey
        for c in range(4):
            for r in range(4):
                s[4 * c + r] ^= (rk[4 * rnd + c] >> (24 - 8 * r)) & 0xFF
    # ronda final: SubBytes + ShiftRows + AddRoundKey
    t = bytearray(16)
    for r in range(4):
        for c in range(4):
            t[4 * c + r] = _SBOX[s[4 * ((c + r) % 4) + r]]
    s = t
    for c in range(4):
        for r in range(4):
            s[4 * c + r] ^= (rk[40 + c] >> (24 - 8 * r)) & 0xFF
    return bytes(s)


def _aes_decrypt_block(rk, block):
    s = bytearray(block)
    for c in range(4):
        for r in range(4):
            s[4 * c + r] ^= (rk[40 + c] >> (24 - 8 * r)) & 0xFF
    for rnd in range(9, 0, -1):
        # InvShiftRows + InvSubBytes
        t = bytearray(16)
        for r in range(4):
            for c in range(4):
                t[4 * c + r] = _INV_SBOX[s[4 * ((c - r) % 4) + r]]
        s = t
        # AddRoundKey
        for c in range(4):
            for r in range(4):
                s[4 * c + r] ^= (rk[4 * rnd + c] >> (24 - 8 * r)) & 0xFF
        # InvMixColumns
        t = bytearray(16)
        for c in range(4):
            a0, a1, a2, a3 = s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]
            t[4 * c] = _gf_mul(a0, 14) ^ _gf_mul(a1, 11) ^ _gf_mul(a2, 13) ^ _gf_mul(a3, 9)
            t[4 * c + 1] = _gf_mul(a0, 9) ^ _gf_mul(a1, 14) ^ _gf_mul(a2, 11) ^ _gf_mul(a3, 13)
            t[4 * c + 2] = _gf_mul(a0, 13) ^ _gf_mul(a1, 9) ^ _gf_mul(a2, 14) ^ _gf_mul(a3, 11)
            t[4 * c + 3] = _gf_mul(a0, 11) ^ _gf_mul(a1, 13) ^ _gf_mul(a2, 9) ^ _gf_mul(a3, 14)
        s = t
    # ronda final: InvShiftRows + InvSubBytes + AddRoundKey
    t = bytearray(16)
    for r in range(4):
        for c in range(4):
            t[4 * c + r] = _INV_SBOX[s[4 * ((c - r) % 4) + r]]
    s = t
    for c in range(4):
        for r in range(4):
            s[4 * c + r] ^= (rk[c] >> (24 - 8 * r)) & 0xFF
    return bytes(s)


def _aes128_cbc_encrypt(data, key, iv):
    if len(data) % 16 != 0:
        pad = 16 - (len(data) % 16)
        data = data + bytes([pad]) * pad
    else:
        data = data + bytes([16]) * 16
    rk = _aes_key_expand(key)
    out = bytearray()
    prev = iv
    for off in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[off:off + 16], prev))
        enc = _aes_encrypt_block(rk, block)
        out.extend(enc)
        prev = enc
    return bytes(out)


def _aes128_cbc_decrypt(data, key, iv):
    """AES-128-CBC con unpadding PKCS#7. Devuelve b"" si falla."""
    if not data or len(data) % 16 != 0:
        return b""
    rk = _aes_key_expand(key)
    out = bytearray()
    prev = iv
    for off in range(0, len(data), 16):
        block = data[off:off + 16]
        dec = _aes_decrypt_block(rk, block)
        out.extend(bytes(a ^ b for a, b in zip(dec, prev)))
        prev = block
    if not out:
        return b""
    pad = out[-1]
    if pad < 1 or pad > 16 or out[-pad:] != bytes([pad]) * pad:
        return b""
    return bytes(out[:-pad])


def _aes256_cbc_decrypt(data, key, iv):
    """AES-256-CBC (misma estructura, expansion de 60 palabras)."""
    if not data or len(data) % 16 != 0:
        return b""
    # expansion AES-256
    w = list(struct.unpack(">8I", key))
    for i in range(8, 60):
        temp = w[i - 1]
        if i % 8 == 0:
            rot = ((temp << 8) | (temp >> 24)) & _M32
            sub = (_SBOX[(rot >> 24) & 0xFF] << 24) | (_SBOX[(rot >> 16) & 0xFF] << 16) \
                | (_SBOX[(rot >> 8) & 0xFF] << 8) | _SBOX[rot & 0xFF]
            temp = sub ^ (_RCON[i // 8 - 1] << 24)
        elif i % 8 == 4:
            temp = (_SBOX[(temp >> 24) & 0xFF] << 24) | (_SBOX[(temp >> 16) & 0xFF] << 16) \
                | (_SBOX[(temp >> 8) & 0xFF] << 8) | _SBOX[temp & 0xFF]
        w.append((w[i - 8] ^ temp) & _M32)
    rk = w
    out = bytearray()
    prev = iv
    for off in range(0, len(data), 16):
        block = data[off:off + 16]
        # decrypt con 14 rondas
        s = bytearray(block)
        for c in range(4):
            for r in range(4):
                s[4 * c + r] ^= (rk[56 + c] >> (24 - 8 * r)) & 0xFF
        for rnd in range(13, 0, -1):
            t = bytearray(16)
            for r in range(4):
                for c in range(4):
                    t[4 * c + r] = _INV_SBOX[s[4 * ((c - r) % 4) + r]]
            s = t
            for c in range(4):
                for r in range(4):
                    s[4 * c + r] ^= (rk[4 * rnd + c] >> (24 - 8 * r)) & 0xFF
            t = bytearray(16)
            for c in range(4):
                a0, a1, a2, a3 = s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]
                t[4 * c] = _gf_mul(a0, 14) ^ _gf_mul(a1, 11) ^ _gf_mul(a2, 13) ^ _gf_mul(a3, 9)
                t[4 * c + 1] = _gf_mul(a0, 9) ^ _gf_mul(a1, 14) ^ _gf_mul(a2, 11) ^ _gf_mul(a3, 13)
                t[4 * c + 2] = _gf_mul(a0, 13) ^ _gf_mul(a1, 9) ^ _gf_mul(a2, 14) ^ _gf_mul(a3, 11)
                t[4 * c + 3] = _gf_mul(a0, 11) ^ _gf_mul(a1, 13) ^ _gf_mul(a2, 9) ^ _gf_mul(a3, 14)
            s = t
        t = bytearray(16)
        for r in range(4):
            for c in range(4):
                t[4 * c + r] = _INV_SBOX[s[4 * ((c - r) % 4) + r]]
        s = t
        for c in range(4):
            for r in range(4):
                s[4 * c + r] ^= (rk[c] >> (24 - 8 * r)) & 0xFF
        out.extend(bytes(a ^ b for a, b in zip(bytes(s), prev)))
        prev = block
    if not out:
        return b""
    pad = out[-1]
    if pad < 1 or pad > 16 or out[-pad:] != bytes([pad]) * pad:
        return b""
    return bytes(out[:-pad])


def _aes256_cbc_encrypt(data, key, iv):
    """AES-256-CBC con padding PKCS#7 (solo para --self-test)."""
    if len(data) % 16 != 0:
        pad = 16 - (len(data) % 16)
        data = data + bytes([pad]) * pad
    else:
        data = data + bytes([16]) * 16
    w = list(struct.unpack(">8I", key))
    for i in range(8, 60):
        temp = w[i - 1]
        if i % 8 == 0:
            rot = ((temp << 8) | (temp >> 24)) & _M32
            sub = (_SBOX[(rot >> 24) & 0xFF] << 24) | (_SBOX[(rot >> 16) & 0xFF] << 16) \
                | (_SBOX[(rot >> 8) & 0xFF] << 8) | _SBOX[rot & 0xFF]
            temp = sub ^ (_RCON[i // 8 - 1] << 24)
        elif i % 8 == 4:
            temp = (_SBOX[(temp >> 24) & 0xFF] << 24) | (_SBOX[(temp >> 16) & 0xFF] << 16) \
                | (_SBOX[(temp >> 8) & 0xFF] << 8) | _SBOX[temp & 0xFF]
        w.append((w[i - 8] ^ temp) & _M32)
    rk = w
    out = bytearray()
    prev = iv
    for off in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[off:off + 16], prev))
        s = bytearray(block)
        for c in range(4):
            for r in range(4):
                s[4 * c + r] ^= (rk[c] >> (24 - 8 * r)) & 0xFF
        for rnd in range(1, 14):
            t = bytearray(16)
            for r in range(4):
                for c in range(4):
                    t[4 * c + r] = _SBOX[s[4 * ((c + r) % 4) + r]]
            s = t
            t = bytearray(16)
            for c in range(4):
                a0, a1, a2, a3 = s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]
                t[4 * c] = _gf_mul(a0, 2) ^ _gf_mul(a1, 3) ^ a2 ^ a3
                t[4 * c + 1] = a0 ^ _gf_mul(a1, 2) ^ _gf_mul(a2, 3) ^ a3
                t[4 * c + 2] = a0 ^ a1 ^ _gf_mul(a2, 2) ^ _gf_mul(a3, 3)
                t[4 * c + 3] = _gf_mul(a0, 3) ^ a1 ^ a2 ^ _gf_mul(a3, 2)
            s = t
            for c in range(4):
                for r in range(4):
                    s[4 * c + r] ^= (rk[4 * rnd + c] >> (24 - 8 * r)) & 0xFF
        t = bytearray(16)
        for r in range(4):
            for c in range(4):
                t[4 * c + r] = _SBOX[s[4 * ((c + r) % 4) + r]]
        s = t
        for c in range(4):
            for r in range(4):
                s[4 * c + r] ^= (rk[56 + c] >> (24 - 8 * r)) & 0xFF
        out.extend(bytes(s))
        prev = bytes(s)
    return bytes(out)


# --------------------------------------------------------------------------
# XXTEA (variante nativa: delta 0x85A92C1F; el descifrado usa sumas
# NEGADAS: empieza en -(rondas*delta) y SUMA delta en cada ronda.
# La ultima palabra del bloque cifrado es la longitud del plaintext.)


def _prepare_xxtea_key(key16):
    """El codigo nativo trunca la clave en el primer byte NUL."""
    k = bytearray(key16[:16].ljust(16, b"\x00"))
    for i in range(15):
        if k[i] == 0:
            for j in range(i + 1, 16):
                k[j] = 0
            break
    return list(struct.unpack("<4I", bytes(k)))


XXTEA_DELTA = 0x85A92C1F


def _xxtea_mx(z, y, total, k):
    return ((((z >> 5) ^ ((y << 2) & _M32)) + ((y >> 3) ^ ((z << 4) & _M32)))
            ^ ((total ^ y) + (k ^ z))) & _M32


def _xxtea_decrypt(data, key16):
    """Puerto exacto de xxtea_decrypt (libovpn3.so). Devuelve (plaintext, len)."""
    n = (len(data) + 3) // 4
    if n < 2 or not data:
        return b"", 0
    buf = bytearray(n * 4)
    buf[:len(data)] = data
    v = list(struct.unpack("<%dI" % n, buf))
    k = _prepare_xxtea_key(key16)
    rounds = 6 + 52 // n
    total = (-(rounds * XXTEA_DELTA)) & _M32
    for _ in range(rounds):
        e = (total >> 2) & 3
        y = v[0]
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - _xxtea_mx(z, y, total, k[(p & 3) ^ e])) & _M32
            y = v[p]
        z = v[n - 1]
        v[0] = (v[0] - _xxtea_mx(z, y, total, k[e])) & _M32
        total = (total + XXTEA_DELTA) & _M32
    total_bytes = n * 4
    last = v[-1]
    if total_bytes - 7 <= last <= total_bytes - 4:
        return struct.pack("<%dI" % n, *v)[:last], last
    return b"", 0


def _xxtea_encrypt(data, key16):
    """Inverso exacto de _xxtea_decrypt (para --self-test)."""
    n = (len(data) + 3) // 4 + 1  # +1: la ultima palabra guarda la longitud
    if n < 2:
        return data
    buf = bytearray(n * 4)
    buf[:len(data)] = data
    v = list(struct.unpack("<%dI" % n, buf))
    v[-1] = len(data)
    k = _prepare_xxtea_key(key16)
    rounds = 6 + 52 // n
    denc = (-XXTEA_DELTA) & _M32
    total = 0
    for _ in range(rounds):
        total = (total + denc) & _M32
        e = (total >> 2) & 3
        z = v[n - 1]
        for p in range(n):
            y = v[(p + 1) % n]
            v[p] = (v[p] + _xxtea_mx(z, y, total, k[(p & 3) ^ e])) & _M32
            z = v[p]
    return struct.pack("<%dI" % n, *v)


# --------------------------------------------------------------------------
# Threefish-256 (Skein; el cifrado de flujo del modo 1)


_C240 = 0x1BD11BDAA9FC1A22
_TF_ROT = [[14, 16], [52, 57], [23, 40], [5, 37],
           [25, 33], [46, 12], [58, 22], [32, 32]]
_TF_PERM = [0, 3, 2, 1]


def _tf_subkeys(key32, tweak):
    k = list(struct.unpack("<4Q", key32))
    k.append(_C240 ^ k[0] ^ k[1] ^ k[2] ^ k[3])
    t = [tweak[0], tweak[1], tweak[0] ^ tweak[1]]
    sk = []
    for s in range(19):
        sk.append([
            k[s % 5],
            (k[(s + 1) % 5] + t[s % 3]) & _M64,
            (k[(s + 2) % 5] + t[(s + 1) % 3]) & _M64,
            (k[(s + 3) % 5] + s) & _M64,
        ])
    return sk


def _rotl64(x, r):
    return ((x << r) | (x >> (64 - r))) & _M64


def _rotr64(x, r):
    return ((x >> r) | (x << (64 - r))) & _M64


def _threefish256_decrypt_block(key32, tweak, block32):
    sk = _tf_subkeys(key32, tweak)
    v = list(struct.unpack("<4Q", block32))
    for r in range(71, -1, -1):
        if (r + 1) % 4 == 0:
            s = (r + 1) // 4
            v = [(v[i] - sk[s][i]) & _M64 for i in range(4)]
        v = [v[_TF_PERM[i]] for i in range(4)]
        r0, r1 = _TF_ROT[r % 8]
        x1 = _rotr64((v[1] ^ v[0]) & _M64, r0)
        x0 = (v[0] - x1) & _M64
        x3 = _rotr64((v[3] ^ v[2]) & _M64, r1)
        x2 = (v[2] - x3) & _M64
        v = [x0, x1, x2, x3]
    v = [(v[i] - sk[0][i]) & _M64 for i in range(4)]
    return struct.pack("<4Q", *v)


def _threefish256_encrypt_block(key32, tweak, block32):
    sk = _tf_subkeys(key32, tweak)
    v = list(struct.unpack("<4Q", block32))
    v = [(v[i] + sk[0][i]) & _M64 for i in range(4)]
    for r in range(72):
        r0, r1 = _TF_ROT[r % 8]
        y0 = (v[0] + v[1]) & _M64
        y1 = _rotl64(v[1], r0) ^ y0
        y2 = (v[2] + v[3]) & _M64
        y3 = _rotl64(v[3], r1) ^ y2
        v = [y0, y1, y2, y3]
        v = [v[_TF_PERM[i]] for i in range(4)]
        if (r + 1) % 4 == 0:
            s = (r + 1) // 4
            v = [(v[i] + sk[s][i]) & _M64 for i in range(4)]
    return struct.pack("<4Q", *v)


# --------------------------------------------------------------------------
# HKDF-SHA256 (RFC 5869) y caracteres invisibles


def _hkdf_sha256(salt, ikm, info=b"", length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, n = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([n]), hashlib.sha256).digest()
        out += t
        n += 1
    return out[:length]


HKDF16 = _hkdf_sha256(FIXED_SALT[:16], SEED, b"", 16)  # key AES modo 1
HKDF32 = _hkdf_sha256(FIXED_SALT, SEED, b"", 32)       # key Threefish modo 1

_ZWSP = "\u200b"  # bit 0
_ZWNJ = "\u200c"  # bit 1
_ZWJ = "\u200d"   # separador, se ignora al decodificar


def _bitswap8(w):
    return ((w << 1) & 0xAA) | ((w >> 1) & 0x55)


def _invisible_decode(s):
    """decode_invisible: ZWSP/ZWNJ -> bits; 8 tokens -> 1 byte;
    intercambio de bits adyacentes; XOR 0x5A."""
    bits = []
    for ch in s:
        if ch == _ZWSP:
            bits.append(0)
        elif ch == _ZWNJ:
            bits.append(1)
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        w = 0
        for b in bits[i:i + 8]:
            w = (w << 1) | b
        out.append(_bitswap8(w) ^ 0x5A)
    return bytes(out)


def _invisible_encode(data):
    """Inverso de _invisible_decode (para --self-test)."""
    out = []
    for byte in data:
        w = _bitswap8(byte ^ 0x5A)
        for i in range(7, -1, -1):
            out.append(_ZWNJ if (w >> i) & 1 else _ZWSP)
        out.append(_ZWJ)  # separador, como en los datos reales
    return "".join(out)


# --------------------------------------------------------------------------
# Los tres modos de RenzUtils.decrypt


def _b64_clean(text):
    if isinstance(text, bytes):
        text = text.decode("ascii", "ignore")
    return "".join(text.split())


def decrypt_mode0(value):
    """Base64 -> AES-128-CBC -> XXTEA. Devuelve bytes o None."""
    if not value:
        return None
    try:
        raw = base64.b64decode(_b64_clean(value), validate=False)
    except Exception:
        return None
    if len(raw) < 16 or len(raw) % 16 != 0:
        return None
    aes_plain = _aes128_cbc_decrypt(raw, AES_KEY, IV)
    if not aes_plain:
        return None
    plain, _ = _xxtea_decrypt(aes_plain, AES_KEY)
    return plain if plain else None


def encrypt_mode0(plain):
    """Inverso de decrypt_mode0 (para --self-test)."""
    x = _xxtea_encrypt(plain, AES_KEY)
    return base64.b64encode(_aes128_cbc_encrypt(x, AES_KEY, IV)).decode("ascii")


def decrypt_mode1(value):
    """Base64 -> Threefish-256 por bloques -> quitar NULs -> AES-128-CBC.
    Devuelve bytes o None."""
    if not value:
        return None
    try:
        raw = base64.b64decode(_b64_clean(value), validate=False)
    except Exception:
        return None
    if len(raw) % 8 != 0:
        return None
    out = bytearray(raw)
    nblocks = (len(raw) + 31) // 32
    for i in range(nblocks):
        chunk = bytes(out[i * 32:(i + 1) * 32])
        if len(chunk) < 32:
            chunk = chunk + b"\x00" * (32 - len(chunk))
        dec = _threefish256_decrypt_block(HKDF32, (i, 192 * i), chunk)
        out[i * 32:(i + 1) * 32] = dec[:len(out[i * 32:(i + 1) * 32])]
    stripped = bytes(out).rstrip(b"\x00")
    if not stripped:
        return None
    # Caso borde: si el cifrado AES termina en 0x00, el strip se come
    # bytes reales del cifrado (el codigo nativo tiene el mismo bug y
    # la app tampoco abre esos campos). Se reponen ceros hasta el
    # siguiente multiplo de 16; el padding PKCS#7 valida el resultado.
    # Ej. real: ServerIPHost luqman3-... y SNIHost scu.eg.
    candidates = []
    if len(stripped) % 16 != 0:
        pad_len = (16 - len(stripped) % 16) % 16
        candidates.append(stripped + b"\x00" * pad_len)
    candidates.append(stripped)
    for cand in candidates:
        if len(cand) % 16 != 0:
            continue
        plain = _aes128_cbc_decrypt(cand, HKDF16, IV)
        if plain:
            return plain
    return None


def encrypt_mode1(plain):
    """Inverso de decrypt_mode1 (para --self-test)."""
    ct = _aes128_cbc_encrypt(plain, HKDF16, IV)
    padded = ct + b"\x00" * ((32 - len(ct) % 32) % 32)
    out = bytearray()
    for i in range(len(padded) // 32):
        out.extend(_threefish256_encrypt_block(HKDF32, (i, 192 * i),
                                               padded[i * 32:(i + 1) * 32]))
    return base64.b64encode(bytes(out)).decode("ascii")


def decrypt_mode2(value):
    """Caracteres invisibles -> XXTEA (PBKDF2) -> AES-256-CBC
    (IV = primeros 16 B). Devuelve bytes o None."""
    if not value:
        return None
    inv = _invisible_decode(value)
    if not inv:
        return None
    x, _ = _xxtea_decrypt(inv, PBKDF2_KEY[:16])
    if not x or len(x) < 32:
        return None
    iv, ct = x[:16], x[16:]
    if len(ct) % 16 != 0:
        return None
    plain = _aes256_cbc_decrypt(ct, PBKDF2_KEY, iv)
    return plain if plain else None


def encrypt_mode2(plain, iv=b"\x00" * 16):
    """Inverso de decrypt_mode2 (para --self-test)."""
    ct = _aes256_cbc_encrypt(plain, PBKDF2_KEY, iv)
    blob = iv + ct
    x = _xxtea_encrypt(blob, PBKDF2_KEY[:16])
    return _invisible_encode(x)


# --------------------------------------------------------------------------
# Catalogo


def fetch_catalog(url=CATALOG_URL):
    """Replica la peticion de la app: GET simple, UA Dalvik. Devuelve
    el cuerpo como texto (una linea Base64)."""
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
    })
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode("utf-8", "ignore")


def decode_envelope(body_text):
    """Descifra el sobre del catalogo (modo 0) -> dict con las claves
    todavia cifradas (Version y Notes vienen en claro)."""
    plain = decrypt_mode0(body_text)
    if not plain:
        raise ValueError("no se pudo descifrar el catalogo (modo 0)")
    return json.loads(plain.decode("utf-8"))


def _looks_encrypted(value):
    """True si el string parece un cifrado (Base64 de longitud valida
    para los modos 0/1, o caracteres invisibles del modo 2)."""
    if not isinstance(value, str) or value == "":
        return False
    if any(c in value for c in (_ZWSP, _ZWNJ, _ZWJ)):
        return True
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        return False
    return len(raw) >= 16 and len(raw) % 16 == 0


def decode_value(value):
    """Descifra un campo del catalogo probando los 3 modos en orden.
    El texto en claro se devuelve tal cual; un cifrado que no abre
    se devuelve como None (no se inventa nada)."""
    if isinstance(value, dict):
        return {k: decode_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [decode_value(v) for v in value]
    if not isinstance(value, str) or value == "":
        return value
    r = decrypt_mode0(value)
    if r is not None:
        return r.decode("utf-8", "replace")
    r = decrypt_mode1(value)
    if r is not None:
        return r.decode("utf-8", "replace")
    r = decrypt_mode2(value)
    if r is not None:
        return r.decode("utf-8", "replace")
    if _looks_encrypted(value):
        return None
    return value


def decode(body_text):
    """Cuerpo crudo del catalogo -> dict legible (servidores y redes
    con todos los campos descifrados)."""
    envelope = decode_envelope(body_text)
    return decode_value(envelope)


def run(url=CATALOG_URL):
    """Descarga el catalogo en vivo, lo descifra y lo resume."""
    body = fetch_catalog(url)
    data = decode(body)
    servers = data.get("Servers", [])
    networks = data.get("Networks", [])
    print("Zam VIP NET — catalogo en vivo")
    print("  Version:", data.get("Version"))
    print("  Notes:", data.get("Notes"))
    print("  Servidores:", len(servers))
    print("  Redes (networks):", len(networks))
    print("  Redes con Payload:", sum(1 for n in networks if n.get("Payload")))
    print("  Redes con SNIHost:", sum(1 for n in networks if n.get("SNIHost")))
    print("  Servidores V2Ray:", sum(1 for s in servers if s.get("V2Ray")))
    print("  Servidores SlowDNS:", sum(1 for s in servers if s.get("SlowDNS")))
    print("  Usuario/clave:", data.get("Username"), "/", data.get("Password"))
    for s in servers[:3]:
        print("  -", s.get("Name"), "|", s.get("ServerIPHost"),
              "|", s.get("Subname"))
    return data


# --------------------------------------------------------------------------
# Self-test


def self_test():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("OK  " if cond else "FAIL") + " " + name)
        if not cond:
            ok = False

    # AES-128 FIPS-197
    key = bytes(range(16))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    rk = _aes_key_expand(key)
    check("AES-128 FIPS-197",
          _aes_encrypt_block(rk, pt).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a")
    check("AES-128 decrypt",
          _aes_decrypt_block(rk, _aes_encrypt_block(rk, pt)) == pt)
    # AES-256 FIPS-197
    key256 = bytes(range(32))
    check("AES-256 FIPS-197",
          _aes256_cbc_encrypt(pt, key256, bytes(16))[:16].hex()
          == "8ea2b7ca516745bfeafc49904b496089")
    # XXTEA round-trip
    import os
    sample = os.urandom(100)
    back, _ = _xxtea_decrypt(_xxtea_encrypt(sample, AES_KEY), AES_KEY)
    check("XXTEA round-trip", back == sample)
    # Threefish round-trip
    blk = os.urandom(32)
    check("Threefish-256 round-trip",
          _threefish256_decrypt_block(HKDF32, (3, 576),
                                      _threefish256_encrypt_block(HKDF32, (3, 576), blk)) == blk)
    # Modo 0 round-trip
    sample_json = json.dumps({"Version": "2.458", "Servers": [
        {"Name": "Test", "ServerIPHost": "example.com"}]},
        ensure_ascii=False).encode("utf-8")
    check("modo 0 round-trip",
          decrypt_mode0(encrypt_mode0(sample_json)) == sample_json)
    # Modo 1 round-trip
    check("modo 1 round-trip",
          decrypt_mode1(encrypt_mode1(b"www.whatsapp.com")) == b"www.whatsapp.com")
    check("modo 1 round-trip (largo)",
          decrypt_mode1(encrypt_mode1(b"A" * 100)) == b"A" * 100)
    # Modo 2 round-trip
    check("modo 2 round-trip",
          decrypt_mode2(encrypt_mode2(b"zambro1")) == b"zambro1")
    # Vectores reales del catalogo en vivo (2026-11-14)
    check("modo 0 vector real",
          decrypt_mode0("zUeLUpDF9cwbOzzp6X788hBm9nojHhSzlRV5WShH09eZ3NI9l7zJ2Jz2EIeMUiAa")
          == "IN Random Server AWS \U0001f195\ufe0f(1)".encode("utf-8"))
    check("modo 1 vector real (ServerIPHost)",
          decrypt_mode1("Pjt+5/dADu5PXRpWBIdp2O67TPLYUtxom/jzAlhgIFU=")
          == b"dssqte46vgrqk.cloudfront.net")
    check("modo 1 vector real (SNIHost)",
          decrypt_mode1("FZXO9NwQcV1XmvcoUIb7pRtODdVkAwa+Bre2hbaHToc=")
          == b"www.whatsapp.com")
    # Caso borde: cifrado AES que termina en 0x00 (el strip nativo se
    # come un byte real; se repone hasta el multiplo de 16).
    check("modo 1 borde 0x00 (ServerIPHost luqman3)",
          decrypt_mode1("UkAEbNV2ey+zC+b+pMqtER/gnjQ9ySafg9w02HiwcreoaC8ixCMA8pQe3nPr44ej3P9Jv1E/m74K516I8TEwCg==")
          == b"luqman3-542877267152.europe-west3.run.app")
    check("modo 1 borde 0x00 (SNIHost scu.eg)",
          decrypt_mode1("nkCek+gvZBZNjzEhGWqF+a2t9ajLx7m0Pdss1ptoL3o=")
          == b"scu.eg")
    print("SELF-TEST:", "TODO OK" if ok else "HAY FALLOS")
    return ok


# --------------------------------------------------------------------------
# CLI


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="Zam VIP NET — decodificador de catalogo")
    ap.add_argument("--url", default=CATALOG_URL,
                    help="URL del catalogo (por defecto, la de la app)")
    ap.add_argument("--out", help="guardar el catalogo legible en este JSON")
    ap.add_argument("--raw-out", help="guardar el sobre descifrado (campos aun cifrados)")
    ap.add_argument("--body", help="descifrar un cuerpo guardado (archivo de texto) en vez de descargar")
    ap.add_argument("--self-test", action="store_true", help="verificar los cifrados y salir")
    args = ap.parse_args(argv)
    if args.self_test:
        return 0 if self_test() else 1
    if args.body:
        with open(args.body, "r", encoding="utf-8", errors="ignore") as f:
            body = f.read()
    else:
        print("Descargando catalogo de", args.url)
        body = fetch_catalog(args.url)
    envelope = decode_envelope(body)
    if args.raw_out:
        with open(args.raw_out, "w", encoding="utf-8") as f:
            json.dump(envelope, f, indent=1, ensure_ascii=False)
        print("Sobre descifrado guardado en", args.raw_out)
    data = decode_value(envelope)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1, ensure_ascii=False)
        print("Catalogo legible guardado en", args.out)
    print("Version:", data.get("Version"))
    print("Servidores:", len(data.get("Servers", [])))
    print("Redes:", len(data.get("Networks", [])))
    print("Usuario/clave:", data.get("Username"), "/", data.get("Password"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
