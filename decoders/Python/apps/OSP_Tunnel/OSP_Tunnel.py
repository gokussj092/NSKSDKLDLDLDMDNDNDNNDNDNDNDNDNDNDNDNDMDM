#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSP Tunnel — decodificador de catalogo para SP-DECODE.
=====================================================
App:        xyz.osptunnel.org 3.7 (build 37), familia RENZ / 7NET
            (renz.javacodez.vpn.*), XAPK APKPure variante arm64-v8a.
            El repo SP-DECODE ya cubre la familia RENZ/7NET en
            decoders/Python/renz.py (.osp y osptunnel:// -> "7net"),
            pero no tiene carpeta propia para OSP Tunnel: este script
            es el catalogo especifico de la app.
Catalogo:   GET https://raw.githubusercontent.com/MAKE-MONEY-MILLION-DOLLAR-PER-DAY/7net-Team/refs/heads/main/7net%2BAll_Team.js
            (Volley StringRequest, sin cabeceras ni auth; la app lo
            pide con el UA Dalvik de Android).
            Respuesta: una sola linea Base64 (774.144 caracteres el
            2026-11-14). Version del catalogo: 40.71.
            81 servidores, 621 redes (networks), usuario/clave
            ksksksk / kslsllsm. Sin distincion gratis/premium en los
            datos (no hay campo IsPremium ni Category).

Esquema (libovpn3.so, RenzUtils.decrypt, 3 modos; constantes .rodata):
  seed (32 B) = deb72221be4652c347f930e85adc29970ccd499cf42e361b3d6b14918912bf3b
  salt fijo   = 70ed508428ff7b5bcde0bcdd3b9474932ab1cabc5ff6870e6e584b4fa7925f55
  IV          = 2d2f3112a271edbba9a41ad58a3a99bf
  Modo 0 (catalogo y la mayoria de campos):
      Base64 -> AES-128-CBC (key = SHA-256(seed)[:16], IV fijo, PKCS#7)
             -> XXTEA (delta 0x7a56d3e1, ultima palabra = longitud)
             -> cada byte - 2
  Modo 1 (ServerIPHost, SNIHost, Payload, V2Ray.PATH/V2RayHost,
          V2Ray.CustomV2RAYConfig):
      Base64 -> Threefish-256 por bloques de 32 B
                (tweak = (n_bloque, 0), key = HKDF-SHA256 de 32 B:
                salt = FIXED_SALT (32 B), IKM = seed, info = "")
             -> quitar NULs finales
             -> AES-128-CBC (key = HKDF-SHA256 de 16 B: salt =
                FIXED_SALT[:16], mismo IV, PKCS#7)
      Caso borde: si el cifrado AES termina en 0x00, el strip nativo
      se come un byte real y la longitud deja de ser multiplo de 16
      (la app tampoco abre esos campos). Se reponen ceros hasta el
      siguiente multiplo de 16; el padding PKCS#7 valida el resultado.
      Ej. reales: Payload de la red 95 y SNIHost de la red 496.
  Modo 2 (Username / Password):
      Base64 -> XXTEA (key = PBKDF2-HMAC-SHA256(seed, FIXED_SALT,
                100000 iters)[:16])
             -> AES-256-CBC (key = PBKDF2 de 32 B,
                IV = primeros 16 B de la salida XXTEA, PKCS#7)

Archivos propios (ver OSP_Tunnel_archivos.py):
  .osp  -> texto, opcionalmente "osptunnel://<cifrado modo 0>" de un
           JSON (o el cifrado directo, o JSON en claro). El repo lo
           registra como extension RENZ ".osp" -> "7net".
  osptunnel://<cifrado>  Enlace de texto: mismo formato; la app lo
           valida ("Error! format must start osptunnel://") y lee
           isSetExpiry / Expiry / isPinEnabled / NetworkPinCode.
           Tambien existe el alias osp:// (mismo formato).
  No hay intent-filter de esquema ni de extension en el manifest:
  la importacion es por pegado de enlace, no por abrir el archivo
  desde otra app.

Solo stdlib. Uso:
  python3 OSP_Tunnel.py [--url URL] [--out JSON] [--raw-out JSON]
  python3 OSP_Tunnel.py --self-test
"""
import base64
import hashlib
import hmac
import json
import struct
import sys
import urllib.request

CATALOG_URL = ("https://raw.githubusercontent.com/"
               "MAKE-MONEY-MILLION-DOLLAR-PER-DAY/7net-Team/"
               "refs/heads/main/7net%2BAll_Team.js")
# User-Agent que usa la app (Volley sobre Android 14, Redmi 14C). El
# cuerpo devuelto es identico con este UA y con el de curl.
USER_AGENT = ("Dalvik/2.1.0 (Linux; U; Android 14; Redmi 14C "
              "Build/UP1A.231005.007)")

# Material criptografico extraido de libovpn3.so (.rodata):
#   seed  @0x27eb08 (32 B), IV @0x27eb28 (16 B), salt @0x27eb74 (32 B).
SEED = bytes.fromhex("deb72221be4652c347f930e85adc29970ccd499cf42e361b3d6b14918912bf3b")
FIXED_SALT = bytes.fromhex("70ed508428ff7b5bcde0bcdd3b9474932ab1cabc5ff6870e6e584b4fa7925f55")
IV = bytes.fromhex("2d2f3112a271edbba9a41ad58a3a99bf")  # IV modo 0 y modo 1
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
# XXTEA (variante nativa: delta 0x85A92C1F = -0x7A56D3E1; el descifrado
# usa sumas NEGADAS: empieza en -(rondas*delta) y SUMA delta en cada
# ronda. Equivale al XXTEA estandar con delta 0x7A56D3E1.
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
# Threefish-256 (Skein; el cifrado de flujo del modo 1).
# OSP usa tweak = (n_bloque, 0) — distinto de Zam (n_bloque, 192*n_bloque).


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
# HKDF-SHA256 (RFC 5869)


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


# --------------------------------------------------------------------------
# Los tres modos de RenzUtils.decrypt


def _b64_clean(text):
    if isinstance(text, bytes):
        text = text.decode("ascii", "ignore")
    return "".join(text.split())


def decrypt_mode0(value):
    """Base64 -> AES-128-CBC -> XXTEA -> cada byte - 2. Devuelve bytes o None."""
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
    if not plain:
        return None
    return bytes((b - 2) & 0xFF for b in plain)


def encrypt_mode0(plain):
    """Inverso de decrypt_mode0 (para --self-test)."""
    shifted = bytes((b + 2) & 0xFF for b in plain)
    x = _xxtea_encrypt(shifted, AES_KEY)
    return base64.b64encode(_aes128_cbc_encrypt(x, AES_KEY, IV)).decode("ascii")


def decrypt_mode1(value):
    """Base64 -> Threefish-256 por bloques (tweak (n, 0)) -> quitar NULs
    -> AES-128-CBC. Devuelve bytes o None."""
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
        dec = _threefish256_decrypt_block(HKDF32, (i, 0), chunk)
        out[i * 32:(i + 1) * 32] = dec[:len(out[i * 32:(i + 1) * 32])]
    stripped = bytes(out).rstrip(b"\x00")
    if not stripped:
        return None
    # Caso borde: si el cifrado AES termina en 0x00, el strip se come
    # bytes reales del cifrado (el codigo nativo tiene el mismo bug y
    # la app tampoco abre esos campos). Se reponen ceros hasta el
    # siguiente multiplo de 16; el padding PKCS#7 valida el resultado.
    # Ej. reales: Payload de la red 95 y SNIHost de la red 496.
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
        out.extend(_threefish256_encrypt_block(HKDF32, (i, 0),
                                               padded[i * 32:(i + 1) * 32]))
    return base64.b64encode(bytes(out)).decode("ascii")


def decrypt_mode2(value):
    """Base64 -> XXTEA (PBKDF2) -> AES-256-CBC (IV = primeros 16 B).
    Devuelve bytes o None."""
    if not value:
        return None
    try:
        raw = base64.b64decode(_b64_clean(value), validate=False)
    except Exception:
        return None
    if len(raw) < 32:
        return None
    x, _ = _xxtea_decrypt(raw, PBKDF2_KEY[:16])
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
    return base64.b64encode(x).decode("ascii")


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
    """True si el string parece un cifrado Base64 de longitud valida
    para los modos 0/1/2."""
    if not isinstance(value, str) or value == "":
        return False
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        return False
    return len(raw) >= 16 and len(raw) % 16 == 0


# Campos que usan un modo distinto del 0 (verificado en el catalogo
# vivo 2026-11-14: 4.794 campos, 0 sin descifrar con este mapeo).
_MODE1_FIELDS = {"ServerIPHost", "SNIHost", "Payload",
                 "CustomV2RAYConfig", "PATH", "V2RayHost"}
_MODE2_FIELDS = {"Username", "Password"}


def _decode_field(name, value):
    """Descifra un campo segun su nombre; si el modo mapeado no abre,
    prueba los otros dos. Devuelve None solo si parece cifrado y
    ningun modo lo abre (no se inventa nada)."""
    if name in _MODE1_FIELDS:
        order = (decrypt_mode1, decrypt_mode0, decrypt_mode2)
    elif name in _MODE2_FIELDS:
        order = (decrypt_mode2, decrypt_mode0, decrypt_mode1)
    else:
        order = (decrypt_mode0, decrypt_mode1, decrypt_mode2)
    for fn in order:
        try:
            r = fn(value)
        except Exception:
            r = None
        if r is not None:
            try:
                s = r.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if all(c in "\n\r\t" or ord(c) >= 32 for c in s):
                return s
    return None if _looks_encrypted(value) else value


def decode_value(value, field_name=None):
    """Descifra un campo (o un dict/lista recursivamente) del catalogo.
    El texto en claro se devuelve tal cual; un cifrado que no abre
    se devuelve como None (no se inventa nada)."""
    if isinstance(value, dict):
        return {k: decode_value(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [decode_value(v, field_name) for v in value]
    if not isinstance(value, str) or value == "":
        return value
    return _decode_field(field_name or "", value)


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
    print("OSP Tunnel — catalogo en vivo")
    print("  Version:", data.get("Version"))
    print("  Notes:", (data.get("Notes") or "")[:80])
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
    # Threefish round-trip (tweak OSP: (n, 0))
    blk = os.urandom(32)
    check("Threefish-256 round-trip",
          _threefish256_decrypt_block(HKDF32, (3, 0),
                                      _threefish256_encrypt_block(HKDF32, (3, 0), blk)) == blk)
    # Modo 0 round-trip
    sample_json = json.dumps({"Version": "40.71", "Servers": [
        {"Name": "Test", "ServerIPHost": "example.com"}]},
        ensure_ascii=False).encode("utf-8")
    check("modo 0 round-trip",
          decrypt_mode0(encrypt_mode0(sample_json)) == sample_json)
    # Modo 1 round-trip
    check("modo 1 round-trip",
          decrypt_mode1(encrypt_mode1(b"www.google.com")) == b"www.google.com")
    check("modo 1 round-trip (largo)",
          decrypt_mode1(encrypt_mode1(b"A" * 100)) == b"A" * 100)
    # Modo 2 round-trip
    check("modo 2 round-trip",
          decrypt_mode2(encrypt_mode2(b"ksksksk")) == b"ksksksk")
    # Vectores reales del catalogo en vivo (2026-11-14)
    check("modo 0 vector real (Name)",
          decrypt_mode0("2iwgVxW6eCixJHyLJBRV9Q==") == "VIP 01".encode("utf-8"))
    check("modo 0 vector real (Subname)",
          decrypt_mode0("gwyjl9pOsztON3f/sFQAbENQLBfShPP8OmD5hzTOpX3i5FQfoPlVrmE2Twx9R1mO")
          == "⚡OVPN Cloudfront Server⚡".encode("utf-8"))
    check("modo 1 vector real (ServerIPHost)",
          decrypt_mode1("e/93oOpcJt5qCJtI5bSoqzjTDGWm5fk9+/3uBz3EsqQ=")
          == b"dyyl4x18ayspo.cloudfront.net")
    check("modo 1 vector real (SNIHost)",
          decrypt_mode1("IDPGVfl8LPJ6hTSMsVyqJQD2cJvBbzB3CA9NWOjnn4k=")
          == b"www.google.com")
    check("modo 1 vector real (Payload)",
          decrypt_mode1("xCPpt4lQPyMqbckhTi9UYlZfHCZyj9rqTSOerQ/zuDJpXX1WyfKJSqe/PNfbb5aqwVyYik4/VkLAWeFnW/HWBD4f0woL8KbHtRY9cmZDGoHeqBEeWv6xDmabaGhJ7hpBUp5kXh+XEB+kes7bKboyNAk7gt3cBZO6fu/HErRJm4k=")
          == b"GET wss://[rotate=[rlb]] HTTP/1.1[crlf]Host: [rotate=[rlb]][crlf]Upgrade: WebServer(Cloudflare)[crlf][crlf]")
    check("modo 2 vector real (Username)",
          decrypt_mode2("8zBr915ZCKPlqY0ha4tFvEuBACBE2P3p8pBwDiPZGYl6D66T")
          == b"ksksksk")
    # Casos borde: cifrado AES que termina en 0x00 (el strip nativo se
    # come un byte real; se repone hasta el multiplo de 16).
    check("modo 1 borde 0x00 (Payload red 95)",
          decrypt_mode1("8clOprhe88qNBeej9b2LqQFz/v497/ttzKE1KBPD/mblL3GEr/0T4bp5ibzX87o6q3+G0s6+qHufx0CJew4mDkTtl75bOFXqNoXo+obRXls0eZGdxU9xrLKsOPDnsXJU")
          == b"GET wss://[rlb] HTTP/1.1[crlf]Host: [rlb][crlf]Upgrade: WebServer(Cloudflare)[crlf][crlf]")
    check("modo 1 borde 0x00 (SNIHost red 496)",
          decrypt_mode1("UxEqy8THsVcln62uqWdozJHleBcIsDOfYpWTpOY9klI=")
          == b"com.telegram.org")
    check("modo 1 borde 0x00 (Payload red 352)",
          decrypt_mode1("sJFPJ0Q2o7Jd06tC3a4bZT+M50j7OSWNaMr5eDdJMdlPhDoLJlRGF+DVyn4BluAmL4pbLj9jcZ2dGfd3PhNYnpcil9OVV2OnMH5ZyUefsWBW6eX0ObQS8NaQQYx9vU/hDSZnuA7M3rglvAWGFVaVck6ZKefgXbXcT16CahH15Po=")
          == b"PUT http://www.mectel.com.mm HTTP/1.0[crlf]Host: http://www.mectel.com.mm[crlf]Connection: keep-alive[crlf][crlf]")
    print("SELF-TEST:", "TODO OK" if ok else "HAY FALLOS")
    return ok


# --------------------------------------------------------------------------
# CLI


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="OSP Tunnel — decodificador de catalogo")
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
