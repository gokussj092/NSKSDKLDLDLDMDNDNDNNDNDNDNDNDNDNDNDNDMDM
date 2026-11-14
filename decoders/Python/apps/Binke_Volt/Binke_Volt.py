#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Binke Volt VPN — decodificador de catalogo para SP-DECODE.
===========================================================
App:        xyz.binkevoltvpn.org 1.1 (build 11), familia RENZ
            (renz.javacodez.vpn.*), XAPK APKPure variante arm64-v8a.
            Sin cobertura previa en el repo (rama
            feat/nuevas-integraciones, 86 apps, 2026-11-14).
Catalogo:   GET https://raw.githubusercontent.com/snapb/B_SHIELD/refs/heads/main/Benben_cnofig.js
            (Volley StringRequest sin cabeceras propias; la app lo pide
            con el UA por defecto de Volley/Dalvik).
            Respuesta: una sola linea Base64 (789.081 caracteres el
            2026-11-14). Version del catalogo: 13.67.
            55 servidores, 789 redes (410 con Payload, 332 con SNIHost),
            usuario/clave binke/binke.

Esquema (libovpn3.so, RenzUtils.decrypt, 3 modos; semilla y IV en
.rodata, 0x27f4a8 y 0x27f4c8; FIXED_SALT en 0x27f514):
  Modo 0 (catalogo y la mayoria de campos):
      Base64 -> AES-128-CBC (key = SHA-256(seed)[:16], IV fijo)
             -> XXTEA (delta 0x85A92C1F, sumas negadas, ultima palabra
                = longitud del plaintext)
             -> restar 2 a cada byte (el nativo lo hace tras el XXTEA;
                al cifrar se suma 2 antes del XXTEA)
  Modo 1 (ServerIPHost, SNIHost, Payload):
      Base64 -> Threefish-256 por bloques de 32 B
                (tweak = (n_bloque, 64*n_bloque), key = HKDF-SHA256
                de 32 B: salt = FIXED_SALT (32 B), IKM = seed, info = "")
             -> quitar NULs finales (con fallback: si el AES no valida,
                se prueba sin quitarlos y reponiendo ceros hasta el
                multiplo de 16; un Payload real, network[592], tiene
                este caso borde: su cifrado AES termina en 0x00)
             -> AES-128-CBC (key = HKDF-SHA256 de 16 B: salt =
                FIXED_SALT[:16], mismo IV)
  Modo 2 (Username / Password, de servidor y del catalogo):
      Base64 -> XXTEA (key = PBKDF2-HMAC-SHA256(seed, FIXED_SALT,
                100000 iters)[:16])
             -> AES-256-CBC (key = PBKDF2 de 32 B,
                IV = primeros 16 B de la salida XXTEA)

Archivos propios (ver Binke_Volt_archivos.py):
  .bvv  -> texto "binkevoltvpn://<cifrado modo 0>" de un perfil JSON
           (ACTION_VIEW en el manifest, pathPattern .*\\.bvv;
           el esquema binkevoltvpn:// se atiende dentro de la app,
           no hay intent-filter con ese scheme en el manifest)
  .js / .rj -> texto con el cifrado modo 0 de un catalogo completo
           (la app comprueba que su campo Version coincida).

Solo stdlib. Uso:
  python3 Binke_Volt.py [--url URL] [--out JSON] [--raw-out JSON]
  python3 Binke_Volt.py --self-test
"""
import base64
import hashlib
import hmac
import json
import struct
import sys
import urllib.request

CATALOG_URL = ("https://raw.githubusercontent.com/snapb/B_SHIELD/"
               "refs/heads/main/Benben_cnofig.js")
# User-Agent que usa la app (Volley sobre Android 14, Redmi 14C).
# La app no pone cabeceras propias: Volley envia su UA Dalvik por
# defecto. El cuerpo devuelto es identico con este UA y con curl.
USER_AGENT = ("Dalvik/2.1.0 (Linux; U; Android 14; Redmi 14C "
              "Build/UP1A.231005.007)")

# Material criptografico extraido de libovpn3.so (.rodata):
SEED = bytes.fromhex("60619246604ae9c8ce17af5e8b271ec82892e321f6ef996d10f21b9535a39f9d")
FIXED_SALT = bytes.fromhex("0e83b2ae50b61547e1d52024ab226ac9d2c0c1f851bb1a62b303b4b8c97af46d")
IV = bytes.fromhex("5befad07d4f0c08b21be7d8179d80966")  # IV modo 0 y modo 1
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






def _b64_clean(text):
    if isinstance(text, bytes):
        text = text.decode("ascii", "ignore")
    return "".join(text.split())


def decrypt_mode0(value):
    """Base64 -> AES-128-CBC -> XXTEA -> restar 2 a cada byte.
    El -2 lo hace el codigo nativo tras el XXTEA (JNI decrypt,
    loop en 0x495394). Devuelve bytes o None."""
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
    """Inverso de decrypt_mode0 (para --self-test y .bvv): se suma 2
    a cada byte antes del XXTEA. Re-cifrar el catalogo en vivo
    reproduce su cuerpo byte a byte (verificado 2026-11-14)."""
    shifted = bytes((b + 2) & 0xFF for b in plain)
    x = _xxtea_encrypt(shifted, AES_KEY)
    return base64.b64encode(_aes128_cbc_encrypt(x, AES_KEY, IV)).decode("ascii")


def decrypt_mode1(value):
    """Base64 -> Threefish-256 por bloques de 32 B (tweak (n, 64n),
    key HKDF32) -> quitar NULs finales -> AES-128-CBC (key HKDF16).
    Devuelve bytes o None.
    Caso borde: si el cifrado AES termina en 0x00, el strip nativo
    se come un byte real (la app tampoco abre ese campo); se prueba
    sin quitar NULs y reponiendo ceros hasta el multiplo de 16.
    Ej. real: Payload de network[592] ("Argentina | Personal")."""
    if not value:
        return None
    try:
        raw = base64.b64decode(_b64_clean(value), validate=False)
    except Exception:
        return None
    if len(raw) % 32 != 0 or not raw:
        return None
    out = bytearray()
    for i in range(len(raw) // 32):
        out += _threefish256_decrypt_block(HKDF32, (i, 64 * i),
                                           raw[i * 32:(i + 1) * 32])
    stripped = bytes(out).rstrip(b"\x00")
    if not stripped:
        return None
    candidates = []
    if len(stripped) % 16 != 0:
        pad_len = (16 - len(stripped) % 16) % 16
        candidates.append(stripped + b"\x00" * pad_len)
    candidates.append(stripped)
    candidates.append(bytes(out))
    for cand in candidates:
        if len(cand) % 16 != 0 or not cand:
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
        out.extend(_threefish256_encrypt_block(HKDF32, (i, 64 * i),
                                               padded[i * 32:(i + 1) * 32]))
    return base64.b64encode(bytes(out)).decode("ascii")


def decrypt_mode2(value):
    """Base64 -> XXTEA (key PBKDF2[:16]) -> AES-256-CBC (key PBKDF2
    de 32 B, IV = primeros 16 B de la salida XXTEA).
    Devuelve bytes o None."""
    if not value:
        return None
    try:
        raw = base64.b64decode(_b64_clean(value), validate=False)
    except Exception:
        return None
    if len(raw) < 4 or len(raw) % 4 != 0:
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
    """True si el string parece un cifrado (Base64 de longitud valida
    para los modos 0/1/2)."""
    if not isinstance(value, str) or value == "":
        return False
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
    print("Binke Volt VPN — catalogo en vivo")
    print("  Version:", data.get("Version"))
    print("  Notes:", data.get("Notes"))
    print("  Servidores:", len(servers))
    print("  Redes (networks):", len(networks))
    print("  Redes con Payload:", sum(1 for n in networks if n.get("Payload")))
    print("  Redes con SNIHost:", sum(1 for n in networks if n.get("SNIHost")))
    print("  Usuario/clave:", data.get("Username"), "/", data.get("Password"))
    for s in servers[:5]:
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
    # Threefish round-trip (tweak Binke: (n, 64n))
    blk = os.urandom(32)
    check("Threefish-256 round-trip",
          _threefish256_decrypt_block(HKDF32, (3, 192),
                                      _threefish256_encrypt_block(HKDF32, (3, 192), blk)) == blk)
    # Modo 0 round-trip
    sample_json = json.dumps({"Version": "13.67", "Servers": [
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
          decrypt_mode2(encrypt_mode2(b"Akbar123")) == b"Akbar123")
    # Vectores reales del catalogo en vivo (2026-11-14, version 13.67)
    check("modo 0 vector real (Name)",
          decrypt_mode0("HfzlhIQQnBdI8QcGupg+1nFBU666MdKsJIXsz582oUCg4XGnfLIcaVbH/6WCXqzG")
          == "Google Cloud Server 01\u26a1\ufe0f".encode("utf-8"))
    check("modo 0 vector real (OpenVPNTCPPort)",
          decrypt_mode0("VWKT4YLFeRZv9x6aLoP+RQ==") == b"1194")
    check("modo 1 vector real (ServerIPHost)",
          decrypt_mode1("V7B6D6lKqHh6D0llKDaZf0CRXZvdQ0qRsWI4B3qkkWT/j8LRhzrwL+zWBzH3kQF9VibaF9q9vO6v8Zqrr4yr2w==")
          == b"binke-386470043281.us-central1.run.app")
    check("modo 1 vector real (SNIHost)",
          decrypt_mode1("iizC4rLL8MKdnTXiMou7gBZjNlzmaP249lBAxBT2jZI=")
          == b"[rlb]")
    check("modo 1 vector real (Payload)",
          decrypt_mode1("/6iv4yvNwHSX80GAeZXCM7zlGLZHhOSo6crspKDWF64NGS0Sk2/yWzYkb9bA"
                        "JpDG8vGSr9qFRJ42xwQxmgYozay7FBRWhXvxZxliiLNiwkYXqQe9lwFTWofuBPYy+gtP")
          .startswith(b"GET wss://[rlb] HTTP/1.1"))
    # Caso borde modo 1: el cifrado AES termina en 0x00 y el strip
    # nativo se comeria un byte real; el fallback lo abre.
    check("modo 1 borde 0x00 (Payload Argentina)",
          decrypt_mode1("yaICjSbzDBw0JCrI8rC/EwM+JfeyUJ4ewjlKnnDSq+j88jiKHqnDsaY2Kl+6"
                        "ClzgKGkWbdSU9AaCqpa5W8helHf9KsCwOBTvTAfCUdM1GplzbWPLPS/BlaDadBGUq+UGQ+"
                        "HBWWlOnny8rcpBukr8XyEkJiKqk99YnI2UkemNamLgvbcOWu7LO0eOQRddygcJqt3+GTjy"
                        "32p4ZYgjSQ3ugrCv9tEOqeZIdghiCZ/jgqwjit815DwibVX6dAnIKCmCD0kQ3635vaZgK/"
                        "vh37sdHXEjk0o7WN3MxFTYQd+sxcdkgExJXrz9x7qAhLexq4HBP01mPU3J40uPisHZSTUxjg==")
          .startswith(b"GET / HTTP/1.1[crlf]Host: ayudaysoporte.personal.com.ar"))
    check("modo 2 vector real (Username servidor)",
          decrypt_mode2("9fP8mc2P2g+XVZltFFSX8A6Pm4/hLyswFjNWH30HfuLE8i2M")
          == b"Akbar123")
    check("modo 2 vector real (Username catalogo)",
          decrypt_mode2("x7vSBdCfHrbrGnkxEDr/k+LQR7pj3CC5gt1bI2ENKzZ93geN")
          == b"binke")
    print("SELF-TEST:", "TODO OK" if ok else "HAY FALLOS")
    return ok

# --------------------------------------------------------------------------
# CLI


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="Binke Volt VPN — decodificador de catalogo")
    ap.add_argument("--url", default=CATALOG_URL,
                    help="URL del catalogo (por defecto, la de la app)")
    ap.add_argument("--out", help="guardar el catalogo legible en este JSON")
    ap.add_argument("--raw-out", help="guardar el sobre descifrado (campos aun cifrados)")
    ap.add_argument("--body", "--file", dest="body",
                    help="descifrar un cuerpo guardado (archivo de texto) en vez de descargar")
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
