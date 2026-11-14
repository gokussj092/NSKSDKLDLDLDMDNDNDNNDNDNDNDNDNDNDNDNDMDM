#!/usr/bin/env python3
"""Lets VPN Go - decodificador de archivos y textos para SP-DECODE.

App: Lets VPN Go, paquete smith.vpn.ko.ni.pro, version 1.7 (versionCode 17).
Fork de v2rayNG de la familia RENZ/7NET (mismo motor que Xhypher Tunnel Pro
y SevenNET VPN). Sin cobertura previa en el repo de SP-DECODE.

Formatos que abre esta app (verificados en el codigo descompilado):
  1. Archivos .js y .rj (LetsVPNGoMain.G): un documento de catalogo
     completo, es decir, el mismo blob Base64 del catalogo (sobre
     exterior modo 0) guardado como texto. La app lo acepta solo si su
     campo "Version" es mayor que la version ya guardada (d50.a).
  2. Textos letsvpngo:// (LetsVPNGoMain.e onClick): un perfil individual
     (servidor + red + protecciones) cifrado con el sobre exterior
     modo 0 y prefijado con "letsvpngo://". Al re-compartir, la app
     anade los campos isSetExpiry, Expiry, isPinEnabled,
     NetworkPinCode y Lock, que viajan en claro dentro del perfil.
  Los archivos .sks NO existen en esta app (0 referencias) y Pedro los
  excluye en cualquier caso.

Cifrado (perfil "letsvpngo" de renz.py, verificado byte a byte en
libovpn3.so del APK: KEY_SEED en 0x1ba9c4, IV en 0x1ba9e4,
FIXED_SALT en 0x1ba9a4). Mismo sobre y mismos modos que el catalogo
(ver Lets_VPN_Go.py):
  sobre exterior: Base64 -> AES-128-CBC (clave SHA-256(KEY_SEED)[:16],
    IV fijo) con PKCS#7 -> XXTEA modificado (delta 0x7A56D3E1,
    rondas 6 + 52/n, ultima palabra = longitud) -> JSON.
    Lets VPN Go NO aplica el paso "-2 por byte" (como xhypher/safetunnel).
  campos modo 0: Name, Subname, OpenVPNTCPPort, OpenVPNSSLPort,
    CloudfrontDNS, flag, Obfs, CustomCert, Info, DNSResolver,
    TLSVersion, NSNameServer, PubKey, UUID, Squid, Port, UpMbps,
    DlMbps, RecvConnectionWindow.
  campos modo 1 (Threefish-256, tweak t1 = indice*192, luego
    AES-128-CBC con HKDF16): ServerIPHost, SNIHost, Payload, PATH,
    V2RayHost, CustomV2RAYConfig.
  campos modo 2 (portador Unicode invisible U+200B/U+200C con U+200D
    de relleno -> XXTEA con PBKDF2-HMAC-SHA256 100000 iters ->
    AES-256-CBC con IV = primeros 16 bytes): Username, Password.
  Version, Notes y los valores simples (Protocol, TunnelType,
  PayloadMode, EnableWS, AutoReplace, UseCustomCert, V2RayType,
  WSType, DNSMode, ReverseAddress, ReverseOnly) van en claro.

Uso:
    Lets_VPN_Go_archivos.py archivo.js
    Lets_VPN_Go_archivos.py archivo.rj
    Lets_VPN_Go_archivos.py "letsvpngo://...."
    Lets_VPN_Go_archivos.py --text "letsvpngo://...."
    cat perfil.txt | Lets_VPN_Go_archivos.py
    Lets_VPN_Go_archivos.py --self-test   prueba offline (sin red)
    Lets_VPN_Go_archivos.py archivo.js -o perfil.json
Un campo que no descifre con ningun modo se deja en claro y se avisa
por stderr (este script es forense: prefiere salida parcial a fallar).
Verificacion: --self-test construye un perfil y un catalogo sinteticos
con este mismo codigo y los abre (round-trip 5/5); ademas el blob real
del catalogo en vivo abre con este script y coincide con la salida de
Lets_VPN_Go.py. No existe ninguna muestra real .js/.rj ni ningun
letsvpngo:// exportado por el telefono, asi que la confirmacion de
extremo a extremo con un archivo real sigue pendiente.
Solo biblioteca estandar de Python 3.10+ (AES, XXTEA y Threefish-256
en Python puro; sin pycryptodome).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import math
import re
import struct
import sys
from pathlib import Path

PROVIDER = "Lets VPN Go"
APP_PACKAGE = "smith.vpn.ko.ni.pro"
APP_VERSION = "1.7 (versionCode 17)"
FILE_EXTENSIONS = (".js", ".rj")

# Perfil "letsvpngo" (renz.py). Verificado byte a byte en libovpn3.so
# (armeabi-v7a) del APK 1.7: KEY_SEED 0x1ba9c4, IV 0x1ba9e4,
# FIXED_SALT 0x1ba9a4.
KEY_SEED = bytes([
    0xD6, 0x86, 0xD5, 0x0A, 0x0B, 0x1F, 0xAE, 0x2D,
    0x42, 0x37, 0xF4, 0xC9, 0x98, 0x0C, 0x26, 0x7A,
    0xDC, 0x52, 0x17, 0x21, 0x17, 0xEA, 0x0B, 0x19,
    0xC2, 0x67, 0x1F, 0xBB, 0x87, 0xB9, 0xF8, 0x10,
])
IV = bytes([
    0xBA, 0x69, 0x31, 0xB3, 0x1B, 0x75, 0x84, 0x58,
    0x0B, 0x71, 0x47, 0x6A, 0xC9, 0xCA, 0x38, 0x9F,
])
FIXED_SALT = bytes([
    0xCB, 0xFE, 0x76, 0x27, 0xE8, 0xD0, 0x36, 0x9A,
    0xFC, 0xD3, 0xD2, 0xD6, 0x4D, 0x9E, 0x09, 0x9B,
    0x13, 0xF7, 0x0F, 0xD8, 0x89, 0x03, 0xB2, 0x66,
    0x67, 0x57, 0x08, 0xD1, 0x88, 0x1E, 0x7A, 0xD6,
])

KEY16 = hashlib.sha256(KEY_SEED).digest()[:16]
MAX_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 32
MAX_NODES = 20000

SCHEME = "letsvpngo://"


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- AES (Python puro, solo stdlib)

_SBOX = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
)
_INV_SBOX = (
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d,
)
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)


def _xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff


def _mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _key_expansion(key):
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = [_SBOX[t[1]] ^ _RCON[i // nk - 1], _SBOX[t[2]],
                 _SBOX[t[3]], _SBOX[t[0]]]
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w, nr


def _add_rk(s, w, rnd):
    for c in range(4):
        for r in range(4):
            s[4 * c + r] ^= w[4 * rnd + c][r]


def _sub(s, inv=False):
    box = _INV_SBOX if inv else _SBOX
    for i in range(16):
        s[i] = box[s[i]]


def _shift(s, inv=False):
    for r in range(1, 4):
        row = [s[4 * c + r] for c in range(4)]
        sh = (4 - r) if inv else r
        row = row[sh:] + row[:sh]
        for c in range(4):
            s[4 * c + r] = row[c]


def _mix(s, inv=False):
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        if inv:
            s[4 * c + 0] = _mul(a[0], 14) ^ _mul(a[1], 11) ^ _mul(a[2], 13) ^ _mul(a[3], 9)
            s[4 * c + 1] = _mul(a[0], 9) ^ _mul(a[1], 14) ^ _mul(a[2], 11) ^ _mul(a[3], 13)
            s[4 * c + 2] = _mul(a[0], 13) ^ _mul(a[1], 9) ^ _mul(a[2], 14) ^ _mul(a[3], 11)
            s[4 * c + 3] = _mul(a[0], 11) ^ _mul(a[1], 13) ^ _mul(a[2], 9) ^ _mul(a[3], 14)
        else:
            s[4 * c + 0] = _mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3]
            s[4 * c + 1] = a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3]
            s[4 * c + 2] = a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3)
            s[4 * c + 3] = _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)


_EXPANSION_CACHE = {}


def _expanded_key(key):
    cached = _EXPANSION_CACHE.get(key)
    if cached is None:
        cached = _key_expansion(key)
        _EXPANSION_CACHE[key] = cached
    return cached


def _aes_encrypt_block(key, block):
    w, nr = _expanded_key(key)
    s = list(block)
    _add_rk(s, w, 0)
    for rnd in range(1, nr):
        _sub(s)
        _shift(s)
        _mix(s)
        _add_rk(s, w, rnd)
    _sub(s)
    _shift(s)
    _add_rk(s, w, nr)
    return bytes(s)


def _aes_decrypt_block(key, block):
    w, nr = _expanded_key(key)
    s = list(block)
    _add_rk(s, w, nr)
    for rnd in range(nr - 1, 0, -1):
        _sub(s, True)
        _shift(s, True)
        _add_rk(s, w, rnd)
        _mix(s, True)
    _sub(s, True)
    _shift(s, True)
    _add_rk(s, w, 0)
    return bytes(s)


def _aes_cbc_encrypt(key, iv, data):
    if len(data) % 16:
        raise ValueError("plaintext length must be a multiple of 16")
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        enc = _aes_encrypt_block(key, blk)
        out += enc
        prev = enc
    return bytes(out)


def _aes_cbc_decrypt(key, iv, data):
    if len(data) % 16:
        raise ValueError("ciphertext length must be a multiple of 16")
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        dec = _aes_decrypt_block(key, blk)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = blk
    return bytes(out)


def _pkcs7_pad(data):
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


def _pkcs7_unpad(data):
    if not data:
        raise ValueError("empty data")
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad PKCS#7 padding")
    return data[:-pad]


# ---------------------------------------------------------------- XXTEA modificado (renz.py)

_XXTEA_DELTA = 0x7A56D3E1  # 2052510689 (RENZ_DELTA_V2)
_XXTEA_OFFSET = 569837754  # RENZ_OFFSET_V2; -6*delta mod 2**32, asi que
# el descifrado corre 6 + 52/n rondas, como el XXTEA estandar.
_MASK32 = 0xFFFFFFFF
_MASK64 = 0xFFFFFFFFFFFFFFFF


def _xxtea_prepare_key(key):
    k = bytearray(key[:16].ljust(16, b"\x00"))
    for i in range(15):
        if k[i] == 0:
            for j in range(i + 1, 16):
                k[j] = 0
            break
    return list(struct.unpack("<4I", k))


def _xxtea_mx(total, y, z, p, e, k):
    return (
        (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
        ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z))
    ) & _MASK32


def _xxtea_to_uint32(data, incl_len):
    wc = (len(data) + 3) // 4
    res = [0] * (wc + (1 if incl_len else 0))
    for i, b in enumerate(data):
        res[i >> 2] |= b << ((i & 3) << 3)
    if incl_len:
        res[wc] = len(data)
    return res


def _xxtea_to_bytes(words, incl_len):
    sz = len(words) * 4
    if incl_len:
        real = words[-1]
        if real < sz - 7 or real > sz - 4:
            raise DecodeError("XXTEA_ERROR", "Longitud XXTEA invalida.")
        sz = real
    out = bytearray(sz)
    for i in range(sz):
        out[i] = (words[i >> 2] >> ((i & 3) << 3)) & 0xFF
    return bytes(out)


def xxtea_decrypt(data, key):
    """XXTEA modificado: devuelve el texto plano (longitud en la ultima palabra)."""
    if not data:
        raise DecodeError("XXTEA_ERROR", "Entrada XXTEA vacia.")
    v = _xxtea_to_uint32(data, False)
    k = _xxtea_prepare_key(key)
    n = len(v)
    if n > 1:
        rounds = 6 + 52 // n
        total = (rounds * _XXTEA_DELTA) & _MASK32
        while total:
            e = (total >> 2) & 3
            y = v[0]
            for p in range(n - 1, 0, -1):
                z = v[p - 1]
                v[p] = (v[p] - _xxtea_mx(total, y, z, p, e, k)) & _MASK32
                y = v[p]
            z = v[n - 1]
            v[0] = (v[0] - _xxtea_mx(total, y, z, 0, e, k)) & _MASK32
            total = (total - _XXTEA_DELTA) & _MASK32
    return _xxtea_to_bytes(v, True)


def xxtea_encrypt(data, key):
    """Inverso de xxtea_decrypt (solo para --self-test)."""
    if not data:
        raise DecodeError("XXTEA_ERROR", "Entrada XXTEA vacia.")
    v = _xxtea_to_uint32(data, True)
    k = _xxtea_prepare_key(key)
    n = len(v)
    if n > 1:
        rounds = 6 + 52 // n
        total = 0
        for _ in range(rounds):
            total = (total + _XXTEA_DELTA) & _MASK32
            e = (total >> 2) & 3
            z = v[n - 1]
            for p in range(n):
                y = v[(p + 1) % n]
                v[p] = (v[p] + _xxtea_mx(total, y, z, p, e, k)) & _MASK32
                z = v[p]
    return _xxtea_to_bytes(v, False)


# ---------------------------------------------------------------- Threefish-256 (renz.py)

_THREEFISH_C240 = 0x1BD11BDAA9FC1A22
_THREEFISH_ROT = ((14, 16), (52, 57), (23, 40), (5, 37),
                  (25, 33), (46, 12), (58, 22), (32, 32))
_THREEFISH_PERM = (0, 3, 2, 1)


def _ror64(v, c):
    return ((v >> c) | (v << (64 - c))) & _MASK64


def _rol64(v, c):
    return ((v << c) | (v >> (64 - c))) & _MASK64


def _threefish_set_key(key_words, tweak):
    kw = list(key_words[:4])
    ks4 = _THREEFISH_C240 ^ kw[0] ^ kw[1] ^ kw[2] ^ kw[3]
    keys = kw + [ks4]
    t0, t1 = tweak[0] & _MASK64, tweak[1] & _MASK64
    tws = [t0, t1, (t0 ^ t1) & _MASK64]
    subkeys = []
    for s in range(19):
        subkeys.append([
            keys[s % 5] & _MASK64,
            (keys[(s + 1) % 5] + tws[s % 3]) & _MASK64,
            (keys[(s + 2) % 5] + tws[(s + 1) % 3]) & _MASK64,
            (keys[(s + 3) % 5] + s) & _MASK64,
        ])
    return subkeys


def _threefish_mix_inv(y0, y1, rot):
    x1 = _ror64(y0 ^ y1, rot)
    x0 = (y0 - x1) & _MASK64
    return x0, x1


def _threefish_mix(x0, x1, rot):
    y0 = (x0 + x1) & _MASK64
    y1 = _rol64(x1, rot) ^ y0
    return y0, y1


def _threefish_decrypt256_block(subkeys, cipher_words, out_words):
    state = list(cipher_words[:4])
    for grp in range(17, -1, -1):
        ak = subkeys[grp + 1]
        for i in range(4):
            state[i] = (state[i] - ak[i]) & _MASK64
        for step in range(3, -1, -1):
            state = [state[_THREEFISH_PERM[i]] for i in range(4)]
            rot = _THREEFISH_ROT[(grp * 4 + step) % 8]
            state[0], state[1] = _threefish_mix_inv(state[0], state[1], rot[0])
            state[2], state[3] = _threefish_mix_inv(state[2], state[3], rot[1])
    ak = subkeys[0]
    for i in range(4):
        state[i] = (state[i] - ak[i]) & _MASK64
    for i in range(4):
        out_words[i] = state[i]


def _threefish_encrypt256_block(subkeys, plain_words, out_words):
    """Inverso de _threefish_decrypt256_block (solo para --self-test)."""
    state = list(plain_words[:4])
    for i in range(4):
        state[i] = (state[i] + subkeys[0][i]) & _MASK64
    for grp in range(18):
        for step in range(4):
            rot = _THREEFISH_ROT[(grp * 4 + step) % 8]
            state[0], state[1] = _threefish_mix(state[0], state[1], rot[0])
            state[2], state[3] = _threefish_mix(state[2], state[3], rot[1])
            state = [state[_THREEFISH_PERM[i]] for i in range(4)]
        ak = subkeys[grp + 1]
        for i in range(4):
            state[i] = (state[i] + ak[i]) & _MASK64
    for i in range(4):
        out_words[i] = state[i]


# ---------------------------------------------------------------- derivacion de claves (renz.py)

def _hkdf_sha256(ikm, salt, length):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, prev, counter = b"", b"", 1
    while len(okm) < length:
        prev = hmac.new(prk, prev + bytes([counter]), hashlib.sha256).digest()
        okm += prev
        counter += 1
    return okm[:length]


HKDF16 = _hkdf_sha256(KEY_SEED, FIXED_SALT[:16], 16)
HKDF32 = _hkdf_sha256(KEY_SEED, FIXED_SALT, 32)
PBKDF32 = hashlib.pbkdf2_hmac("sha256", KEY_SEED, FIXED_SALT, 100000, 32)


# ---------------------------------------------------------------- portador Unicode invisible (Xhypher)

_INVISIBLE = "\u200b\u200c\u200d"


def decode_invisible(text):
    """U+200B/U+200C codifican bits; U+200D es relleno sin datos."""
    if not text or any(c not in _INVISIBLE for c in text):
        raise DecodeError("CARRIER_ERROR", "Portador invisible invalido.")
    out = bytearray()
    value = count = 0
    for c in text:
        if c == "\u200d":
            continue
        value = (value << 1) | int(c == "\u200c")
        count += 1
        if count == 8:
            out.append((((value & 0xAA) >> 1) | ((value & 0x55) << 1)) ^ 0x5A)
            value = count = 0
    if count or not out:
        raise DecodeError("CARRIER_ERROR", "Portador invisible incompleto.")
    return bytes(out)


def encode_invisible(data):
    """Inverso de decode_invisible (solo para --self-test)."""
    chars = []
    for b in data:
        v = (((b ^ 0x5A) & 0xAA) >> 1) | (((b ^ 0x5A) & 0x55) << 1)
        for bit in range(7, -1, -1):
            chars.append("\u200c" if (v >> bit) & 1 else "\u200b")
    return "".join(chars)


# ---------------------------------------------------------------- modos de campo (Xhypher, material letsvpngo)

def _b64(text):
    if not isinstance(text, str) or not text or len(text.encode("utf-8")) > MAX_BYTES:
        raise DecodeError("FORMAT_ERROR", "Campo Base64 invalido.")
    try:
        return base64.b64decode("".join(text.split()), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DecodeError("FORMAT_ERROR", "Base64 invalido.") from exc


def decode_main(text):
    """Modo 0: Base64 -> AES-128-CBC (KEY16, IV) -> XXTEA -> UTF-8."""
    raw = _b64(text)
    if not raw or len(raw) % 16:
        raise DecodeError("FORMAT_ERROR", "Sobre CBC invalido.")
    try:
        plain = _pkcs7_unpad(_aes_cbc_decrypt(KEY16, IV, raw))
        return xxtea_decrypt(plain, KEY16).decode("utf-8")
    except (DecodeError, ValueError, UnicodeError) as exc:
        raise DecodeError("DECRYPT_ERROR", "No se pudo descifrar (modo 0).") from exc


def encode_main(text):
    """Inverso de decode_main (solo para --self-test)."""
    inner = xxtea_encrypt(text.encode("utf-8"), KEY16)
    return base64.b64encode(_aes_cbc_encrypt(KEY16, IV, _pkcs7_pad(inner))).decode("ascii")


def decode_special(text):
    """Modo 1: Base64 -> Threefish-256 (tweak t1 = indice*192) ->
    AES-128-CBC (HKDF16, IV) -> UTF-8."""
    raw = _b64(text)
    if not raw or len(raw) % 32:
        raise DecodeError("FORMAT_ERROR", "Bloques Threefish incompletos.")
    words = list(struct.unpack("<4Q", HKDF32))
    clear = bytearray()
    for offset in range(0, len(raw), 32):
        index = offset // 32
        subkeys = _threefish_set_key(words, [index, index * 192])
        out = [0, 0, 0, 0]
        _threefish_decrypt256_block(
            subkeys, list(struct.unpack("<4Q", raw[offset:offset + 32])), out)
        clear.extend(struct.pack("<4Q", *out))
    # Recorte nativo de ceros hasta el siguiente limite CBC.
    size = ((len(bytes(clear).rstrip(b"\0")) + 15) // 16) * 16
    clear = bytes(clear[:size])
    if not clear or len(clear) % 16:
        raise DecodeError("FORMAT_ERROR", "Contenido Threefish/CBC invalido.")
    try:
        return _pkcs7_unpad(_aes_cbc_decrypt(HKDF16, IV, clear)).decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("DECRYPT_ERROR", "No se pudo descifrar (modo 1).") from exc


def encode_special(text):
    """Inverso de decode_special (solo para --self-test)."""
    data = _aes_cbc_encrypt(HKDF16, IV, _pkcs7_pad(text.encode("utf-8")))
    data += b"\x00" * ((-len(data)) % 32)
    words = list(struct.unpack("<4Q", HKDF32))
    out = bytearray()
    for offset in range(0, len(data), 32):
        index = offset // 32
        subkeys = _threefish_set_key(words, [index, index * 192])
        enc = [0, 0, 0, 0]
        _threefish_encrypt256_block(
            subkeys, list(struct.unpack("<4Q", data[offset:offset + 32])), enc)
        out.extend(struct.pack("<4Q", *enc))
    return base64.b64encode(bytes(out)).decode("ascii")


def decode_sensitive(text):
    """Modo 2: portador invisible (o Base64) -> XXTEA (PBKDF32) ->
    AES-256-CBC con IV = primeros 16 bytes -> UTF-8."""
    raw = decode_invisible(text) if any(c in text for c in _INVISIBLE) else _b64(text)
    try:
        clear = xxtea_decrypt(raw, PBKDF32)
    except DecodeError as exc:
        raise DecodeError("DECRYPT_ERROR", "No se pudo descifrar (modo 2).") from exc
    if len(clear) < 32 or len(clear) % 16:
        raise DecodeError("FORMAT_ERROR", "Sobre de credenciales invalido.")
    try:
        return _pkcs7_unpad(
            _aes_cbc_decrypt(PBKDF32, clear[:16], clear[16:])).decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("DECRYPT_ERROR", "No se pudo descifrar (modo 2).") from exc


def encode_sensitive(text):
    """Inverso de decode_sensitive (solo para --self-test; IV fijo)."""
    iv = bytes(range(16))
    ct = _aes_cbc_encrypt(PBKDF32, iv, _pkcs7_pad(text.encode("utf-8")))
    return encode_invisible(xxtea_encrypt(iv + ct, PBKDF32))


_MODE_DECODE = (decode_main, decode_special, decode_sensitive)
_MODE_ENCODE = (encode_main, encode_special, encode_sensitive)


# ---------------------------------------------------------------- esquema de campos (verificado con el catalogo en vivo)

# Nombre de campo -> modo (0, 1 o 2). El mismo nombre siempre usa el mismo
# modo en todo el documento (servidores, redes y sub-objetos).
FIELD_MODE = {
    # modo 0
    "Name": 0, "Subname": 0, "OpenVPNTCPPort": 0, "OpenVPNSSLPort": 0,
    "CloudfrontDNS": 0, "flag": 0, "Obfs": 0, "CustomCert": 0,
    "Info": 0, "DNSResolver": 0, "TLSVersion": 0,
    "NSNameServer": 0, "PubKey": 0, "UUID": 0,
    "Squid": 0, "Port": 0, "UpMbps": 0, "DlMbps": 0,
    "RecvConnectionWindow": 0,
    # modo 1
    "ServerIPHost": 1, "SNIHost": 1, "Payload": 1,
    "PATH": 1, "V2RayHost": 1, "CustomV2RAYConfig": 1,
    # modo 2
    "Username": 2, "Password": 2,
}
# Campos en claro que nunca se descifran (valores simples o protecciones).
PLAIN_FIELDS = {
    "Version", "Notes", "Protocol", "ServerHTTP", "UseCustomCert",
    "TunnelType", "DNSServerHost", "AutoReplace", "EnableWS",
    "PayloadMode", "V2RayType", "UseCustomV2RAYConfig",
    "isSetExpiry", "Expiry", "isPinEnabled", "NetworkPinCode", "Lock",
}


WARNINGS = []


def _decrypt_value(value, field, where):
    """Descifra un campo con su modo; si falla prueba los otros dos modos.

    Si ningun modo abre el campo, lo deja en claro y registra un aviso
    (este script es forense: prefiere salida parcial a fallar entero).
    """
    if not isinstance(value, str) or value == "":
        return value
    mode = FIELD_MODE.get(field)
    if mode is None:
        return value
    tried = [mode, 0, 1, 2]
    seen = set()
    for m in tried:
        if m in seen:
            continue
        seen.add(m)
        try:
            return _MODE_DECODE[m](value)
        except DecodeError:
            continue
    WARNINGS.append("Campo %s.%s sin descifrar (ningun modo)." % (where, field))
    return value


def _decrypt_object(obj, where):
    """Descifra recursivamente un dict de perfil/servidor/red."""
    out = {}
    for key, value in obj.items():
        if isinstance(value, dict):
            out[key] = _decrypt_object(value, "%s.%s" % (where, key))
        elif isinstance(value, list):
            out[key] = [
                _decrypt_object(item, "%s.%s[%d]" % (where, key, i))
                if isinstance(item, dict) else item
                for i, item in enumerate(value)]
        elif key in FIELD_MODE:
            out[key] = _decrypt_value(value, key, where)
        else:
            out[key] = value
    return out


def decrypt_document(doc):
    """Descifra un documento ya parseado (catalogo completo o perfil)."""
    if not isinstance(doc, dict):
        raise DecodeError("WRONG_DOCUMENT", "El documento debe ser un objeto JSON.")
    return _decrypt_object(doc, "$")


# ---------------------------------------------------------------- API offline (formato de proveedor del repo)

def _text(data):
    if not isinstance(data, (bytes, str)):
        raise DecodeError("FORMAT_ERROR", "Se esperaba texto o bytes UTF-8.")
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La entrada supera el limite de tamano.")
    try:
        value = data.decode("utf-8-sig") if isinstance(data, bytes) else data.removeprefix("\ufeff")
        if len(value.encode("utf-8")) > MAX_BYTES:
            raise DecodeError("SIZE_LIMIT", "La entrada supera el limite de tamano.")
    except UnicodeError as exc:
        raise DecodeError("FORMAT_ERROR", "La entrada no es UTF-8 valido.") from exc
    return value.strip()


def _base64_blob(text):
    compact = re.sub(r"[ \t\r\n]", "", text)
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact) or len(compact) % 4 == 1:
        raise DecodeError("FORMAT_ERROR", "Se esperaba Base64 estandar.")
    try:
        return base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DecodeError("FORMAT_ERROR", "Base64 invalido.") from exc


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
            raise DecodeError("SIZE_LIMIT", "El JSON supera el limite de complejidad.")
        if isinstance(value, dict):
            pending.extend((v, depth + 1) for v in value.values())
            pending.extend((k, depth + 1) for k in value)
        elif isinstance(value, list):
            pending.extend((v, depth + 1) for v in value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise DecodeError("INVALID_JSON", "Numero JSON no finito.")
        elif isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeError as exc:
                raise DecodeError("INVALID_JSON", "Unicode JSON invalido.") from exc
    return doc


def _json(data):
    try:
        doc = json.loads(data, object_pairs_hook=_unique, parse_constant=_nonfinite)
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("INVALID_JSON", "El contenido no es JSON valido.") from exc
    return _validate(doc)



# ---------------------------------------------------------------- API offline (archivos y textos)

def _strip_scheme(text):
    """Quita el prefijo letsvpngo:// si esta presente."""
    value = text.strip()
    if value.lower().startswith(SCHEME):
        return value[len(SCHEME):]
    return value


def decode_input(data):
    """Descifra un archivo .js/.rj o un texto letsvpngo:// y devuelve su dict.

    Acepta bytes o str: el contenido de un archivo, el texto completo con
    el esquema, o el blob Base64 sin esquema. El sobre exterior es el
    modo 0; despues se descifran los campos por su esquema (catalogo
    completo o perfil individual).
    """
    WARNINGS.clear()
    plain = decode_main(_strip_scheme(_text(data)))
    doc = _json(plain)
    if not isinstance(doc, dict):
        raise DecodeError("WRONG_DOCUMENT", "El documento debe ser un objeto JSON.")
    return decrypt_document(doc)


def decode(data):
    """Offline API: igual que decode_input (alias del formato de proveedor)."""
    return decode_input(data)


def run(file_bytes):
    """Offline API: JSON completo del archivo/texto o None; nunca parcial."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


def _read(path):
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el limite de tamano.")
    return data


def _encrypt_object(obj):
    """Cifra un dict claro con su esquema (solo para --self-test)."""
    out = {}
    for key, value in obj.items():
        if isinstance(value, dict):
            out[key] = _encrypt_object(value)
        elif isinstance(value, list):
            out[key] = [_encrypt_object(item) if isinstance(item, dict) else item
                        for item in value]
        elif key in FIELD_MODE and isinstance(value, str) and value:
            out[key] = _MODE_ENCODE[FIELD_MODE[key]](value)
        else:
            out[key] = value
    return out


# ---------------------------------------------------------------- self-test offline

def _self_test():
    checks = 0

    # 1. AES: vector FIPS-197 (AES-128) y round-trip CBC 128/256.
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert _aes_encrypt_block(key, block).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a", "AES-128 FIPS-197"
    assert _aes_decrypt_block(key, bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")) == block, "AES-128 inversa"
    checks += 2
    import os
    for klen in (16, 32):
        k = os.urandom(klen)
        iv = os.urandom(16)
        pt = os.urandom(160)
        assert _aes_cbc_decrypt(k, iv, _aes_cbc_encrypt(k, iv, pt)) == pt, "AES-CBC %d" % (klen * 8)
        checks += 1

    # 2. XXTEA: round-trip en varias longitudes.
    for size in (1, 5, 16, 17, 100, 1000):
        pt = os.urandom(size)
        assert xxtea_decrypt(xxtea_encrypt(pt, KEY16), KEY16) == pt, "XXTEA %d" % size
        checks += 1

    # 3. Threefish-256: round-trip por bloque.
    words = list(struct.unpack("<4Q", HKDF32))
    for idx in (0, 1, 5):
        sub = _threefish_set_key(words, [idx, idx * 192])
        plain = [0x0123456789ABCDEF, 0xFEDCBA9876543210, 0x1111222233334444, 0xAAAABBBBCCCCDDDD]
        enc = [0, 0, 0, 0]
        dec = [0, 0, 0, 0]
        _threefish_encrypt256_block(sub, plain, enc)
        _threefish_decrypt256_block(sub, enc, dec)
        assert dec == plain, "Threefish-256 bloque %d" % idx
        checks += 1

    # 4. Portador invisible: round-trip.
    raw = os.urandom(64)
    assert decode_invisible(encode_invisible(raw)) == raw, "portador invisible"
    checks += 1

    # 5. Modos 0/1/2: cifrar -> descifrar con texto variado (Unicode, emoji).
    samples = ["Hola 🌍", "web.ejemplo.test", "443", "VodaCom|Uɴʟɪᴍɪᴛᴇᴅ",
               "letsvpngo", '{"a": 1, "b": [true, null]}', "x" * 500]
    for sample in samples:
        for mode in (0, 1, 2):
            assert _MODE_DECODE[mode](_MODE_ENCODE[mode](sample)) == sample, "modo %d" % mode
            checks += 1

    # 6. Perfil sintetico letsvpngo://: servidor + red + protecciones.
    profile = {
        "Server": {
            "Name": "⚡Servidor de prueba ZA",
            "ServerIPHost": "web.ejemplo.test",
            "Subname": "prueba °ssl°",
            "OpenVPNTCPPort": "80", "OpenVPNSSLPort": "443",
            "Protocol": 1, "CloudfrontDNS": "", "ServerHTTP": "",
            "flag": "za", "Obfs": "", "Username": "usuario_prueba",
            "Password": "clave_prueba", "UseCustomCert": False,
            "CustomCert": "",
            "SlowDNS": {"NSNameServer": "ns.ejemplo.test",
                        "PubKey": "AAECAwQFBg=="},
            "V2Ray": {"V2RayType": 2,
                      "UUID": "11111111-2222-3333-4444-555555555555",
                      "PATH": "/ruta", "V2RayHost": "v2.ejemplo.test"},
        },
        "Network": {
            "Name": "Red de prueba | Uɴʟɪᴍɪᴛᴇᴅ",
            "SNIHost": "sni.ejemplo.test",
            "Payload": "GET / HTTP/1.1\r\nHost: ejemplo.test\r\n\r\n",
            "Info": "info de prueba 🌍", "TunnelType": 9,
            "DNSServerHost": "", "DNSResolver": "1.1.1.1",
            "AutoReplace": True, "TLSVersion": "Default",
            "EnableWS": False,
            "V2Ray": {"UseCustomV2RAYConfig": True,
                      "CustomV2RAYConfig": '{"dns": {"hosts": {}}}',
                      "SNIHost": "v2sni.ejemplo.test"},
            "PayloadMode": 0,
            "ProxySettings": {"Squid": "proxy.ejemplo.test", "Port": "8080"},
            "UDPOptions": {"UpMbps": "10", "DlMbps": "20",
                           "RecvConnectionWindow": "1024"},
        },
        "isSetExpiry": True, "Expiry": "2027-01-31",
        "isPinEnabled": True, "NetworkPinCode": "1234", "Lock": False,
    }
    link = SCHEME + encode_main(json.dumps(_encrypt_object(profile), ensure_ascii=False))
    assert decode_input(link) == profile, "perfil letsvpngo://"
    checks += 1
    # El mismo perfil sin esquema (blob pelado) tambien abre.
    assert decode_input(link[len(SCHEME):]) == profile, "perfil sin esquema"
    checks += 1

    # 7. Archivo .js sintetico: un catalogo completo como lo guarda la app.
    doc = {"Version": "654", "Servers": [profile["Server"]],
           "Networks": [profile["Network"]],
           "Username": "doc_usuario", "Password": "doc_clave",
           "Notes": "Nota de prueba"}
    blob = encode_main(json.dumps(_encrypt_object(doc), ensure_ascii=False))
    assert decode_input(blob) == doc, "archivo .js sintetico"
    checks += 1
    # run() devuelve el JSON completo.
    assert json.loads(run(blob.encode("ascii"))) == doc, "run()"
    checks += 1
    assert not WARNINGS, "avisos inesperados: %s" % WARNINGS
    print("SELF-TEST OK (%d comprobaciones)" % checks)
    return 0


# ---------------------------------------------------------------- CLI

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("file", nargs="?", type=Path,
                        help="Archivo .js/.rj o texto letsvpngo:// guardado")
    source.add_argument("--text", help="Texto letsvpngo:// o blob Base64")
    source.add_argument("--self-test", action="store_true", help="Prueba offline sin red")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo; por defecto stdout")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    try:
        if args.text is not None:
            data = args.text.encode("utf-8")
        elif args.file is not None:
            data = _read(args.file)
        else:
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise DecodeError("SIZE_LIMIT", "La entrada supera el limite de tamano.")
        result = decode(data)
        rendered = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        for warning in WARNINGS:
            print("AVISO: %s" % warning, file=sys.stderr)
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
