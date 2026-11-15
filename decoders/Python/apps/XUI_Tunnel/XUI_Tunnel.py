#!/usr/bin/env python3
"""XUI Tunnel VPN 6.0 (com.xui_tunnel): catalog decoder, local or explicit HTTPS.

Standalone Python 3.10+, standard library only; no APK needed at runtime.
See README.md here.

Method (verified against this APK, versionCode 6, versionName 6.0;
NoobCrypt / NoobDev framework; the SP-DECODE repo covers the .xui
FILE format only -- decoders/Python/xui.py + _noobcrypt.py -- and has
NO catalog provider for XUI as of 2026-11-14):

  GET https://deeptun.xyz/api/app?json=fb05d52c82789ba38e2a
  (HTTPS GET, HttpURLConnection; plain GET, no custom headers, no
  authentication, no parameters; connect/read timeout 8,000 ms each;
  the app reads the body line by line and concatenates the lines.
  On a non-200 response or an empty URL the app retries once with
  https://backup.com.link. Verified live 2026-11-14.)
  -> body is one line of standard Base64 (914,852 bytes live)
  -> NoobCrypt.b(body, 5, false): AES-256-XTS, 64-byte key
     KEY_CONFIG5, tweak (IV) = first 16 bytes of the Base64-decoded
     body, ciphertext = the rest (ciphertext stealing for the final
     partial block, IEEE 1619)
  -> JSON with Version, Message, DefUpdateURL, updater, updatemsg,
     cardMessage, cardLink, defTime, addTime, bonus, versioncode,
     Servers[] and Tweaks[] (the app calls them "Tweaks", other
     batches call them networks/payloads)
  -> every string value inside the JSON is itself encrypted:
       * Servers[] (and the nested V2ray UUID/Path) and the top-level
         fields: NoobCrypt.b(value, 0, false) =
         Base64(nonce[12] + ct + tag[16]), AES-256-GCM, KEY_FIELD.
       * Tweaks[] string fields (Name, Info, Sni, Payload, ProxyHost,
         ProxyPort, DNSHost, v2rayjson, ...): NoobCrypt.b(value, 1,
         false) = Base64(IV[16] + ct), AES-256-CBC, KEY_FIELD,
         PKCS#7 padding. The tweak Flag ("NOOB_DEV") is plaintext.
     GCM authentication makes the index-0 probe safe; a CBC value is
     accepted only when it Base64-decodes, unpads cleanly and yields
     valid UTF-8. A value that decrypts with neither index is left
     as-is (plaintext).

Keys (public app-wide format constants, recovered from libovpn3.so;
NOT account credentials):
  KEY_FIELD (32 bytes, NoobCrypt index 0/1/3/4): the plain XOR of two
      .rodata chunks, verified byte-for-byte against the repo's
      decoders/Python/_noobcrypt.py KEYS["xui"]:
      file[0x21e240:0x21e250] ^ file[0x1c2b80:0x1c2b90] ||
      file[0x21e250:0x21e260] ^ file[0x1c2860:0x1c2870]
      -> 721d60cba2999a7e0f90e848d1ea31b7d06aa6be3654821fc4a5b388e70fc51c
  KEY_CONFIG5 (64 bytes, NoobCrypt index 5, AES-256-XTS): four 16-byte
      chunks, each ROL6(chunk_a XOR chunk_b) per byte
      (ROL6 = rotate-left by 6 = ((b << 6) & 0xff) | (b >> 2)):
      K0 = ROL6(file[0x21e490:0x21e4a0] ^ file[0x1c2000:0x1c2010])
      K1 = ROL6(file[0x21e4a0:0x21e4b0] ^ file[0x1c21c0:0x1c21d0])
      K2 = ROL6(file[0x21e4b0:0x21e4c0] ^ file[0x1c2aa0:0x1c2ab0])
      K3 = ROL6(file[0x21e4c0:0x21e4d0] ^ file[0x1c2ab0:0x1c2ac0])
      -> 75dd40d75d069f98ddea21fe877ee6c9a82618a6c984f450f06f2e3e1e7e03
         06d37ce7ffed346eef5d0b3f7dece5c4bb7b86f24199fc21ccde99153c1a1ba799
      Both keys were confirmed by running the native NoobCrypt.b in
      libovpn3.so under Unicorn and capturing the key passed to
      EVP_DecryptInit_ex; the pure-Python XTS decrypt then reproduced
      the native plaintext byte-for-byte.

Live test (2026-11-14, --url): HTTP 200, 914,852 bytes,
SHA-256 72e52bc3786804def2fc3c260c8290648c341319c34bc344027c999b8a47c6a0,
catalog version 1.2.82, 47 servers (27 NoobLevel 0, 20 NoobLevel 1;
protocols 17 OVPN, 16 V2Ray, 5 UDP, 5 SLOW DNS, 4 SSH; 16 with a
V2ray section), 680 tweaks, 370 with a Payload, 379 with an SNI.
All server and tweak string values decrypt (0 failures); the
DefUpdateURL in the live catalog is the same URL that was fetched.
Bundled seed config (res/raw/noobdev.js, the first-run config):
version 1.0.1, 1 server, 1 tweak (placeholders: www.server.com,
"Update Config Version"); used by --self-test. Its DefUpdateURL is
the same live URL, so the bundled config and the live catalog agree.

File formats: the app opens .xui files (VIEW intent-filter on
ImportActivity, content/file schemes, mimeType */*, pathPattern
.*\\.xui). A .xui file is Base64(IV[16] + AES-256-CBC(KEY_FIELD)
("XUI Tunnel VPN" + JSON)); see XUI_Tunnel_archivos.py. The app
declares NO custom URI scheme (no xui://), so there is no text-link
scheme to decode. The catalog's servers contain standard vless://
links as decrypted values; those protocols are already covered by
SP-DECODE.
"""
from __future__ import annotations

import argparse
import base64
import json
import math
import struct
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

MAX_BYTES = 5 * 1024 * 1024
MAX_OUTPUT = 4 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
CATALOG_URL = "https://deeptun.xyz/api/app?json=fb05d52c82789ba38e2a"
BACKUP_URL = "https://backup.com.link"
USER_AGENT = "Dalvik/2.1.0 (Linux; U; Android 14; Redmi 14C Build/UQ1A.240205.002)"
LIST_FIELDS = ("Servers", "Tweaks")
APP_NAME = "XUI Tunnel VPN"

KEY_CONFIG5 = bytes.fromhex(
    "75dd40d75d069f98ddea21fe877ee6c9a82618a6c984f450f06f2e3e1e7e03"
    "06d37ce7ffed346eef5d0b3f7dece5c4bb7b86f24199fc21ccde99153c1a1ba799")
KEY_FIELD = bytes.fromhex(
    "721d60cba2999a7e0f90e848d1ea31b7d06aa6be3654821fc4a5b388e70fc51c")

# The app's shipped first-run seed config (res/raw/noobdev.js, 3,104
# chars, single Base64 line); a real test vector from the APK itself,
# used by --self-test. Decrypts (index 5) to version 1.0.1, 1 server,
# 1 tweak.
SEED_BLOB = (
    "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"
    "Ayq5"
)


class DecodeError(ValueError):
    """Error de descifrado con un código estable para SP-DECODE."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------- AES-256 puro
# Núcleo AES en Python puro con T-tables (SubBytes+ShiftRows+
# MixColumns en 4 tablas de 256 entradas): ~30x más rápido que
# la versión ingenua y verificado contra PyCryptodome (vector
# FIPS-197 y 200 vectores aleatorios). El descifrado usa el
# cifrado inverso equivalente: las claves de ronda 1..13 van
# transformadas por InvMixColumns (se cachean por clave).
import struct

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
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

def _xtime(x):
    return ((x << 1) ^ (0x1b if x & 0x80 else 0)) & 0xff

def _mul(x, n):
    r = 0
    while n:
        if n & 1:
            r ^= x
        x = _xtime(x)
        n >>= 1
    return r

def _make_tables():
    Te0, Te1, Te2, Te3 = [], [], [], []
    Td0, Td1, Td2, Td3 = [], [], [], []
    for i in range(256):
        s = _SBOX[i]
        s2 = _mul(s, 2)
        s3 = _mul(s, 3)
        Te0.append((s2 << 24) | (s << 16) | (s << 8) | s3)
        Te1.append((s3 << 24) | (s2 << 16) | (s << 8) | s)
        Te2.append((s << 24) | (s3 << 16) | (s2 << 8) | s)
        Te3.append((s << 24) | (s << 16) | (s3 << 8) | s2)
        isb = _INV_SBOX[i]
        m9, m11, m13, m14 = _mul(isb, 9), _mul(isb, 11), _mul(isb, 13), _mul(isb, 14)
        Td0.append((m14 << 24) | (m9 << 16) | (m13 << 8) | m11)
        Td1.append((m11 << 24) | (m14 << 16) | (m9 << 8) | m13)
        Td2.append((m13 << 24) | (m11 << 16) | (m14 << 8) | m9)
        Td3.append((m9 << 24) | (m13 << 16) | (m11 << 8) | m14)
    return (Te0, Te1, Te2, Te3), (Td0, Td1, Td2, Td3)

_TE, _TD = _make_tables()
_Te0, _Te1, _Te2, _Te3 = _TE
_Td0, _Td1, _Td2, _Td3 = _TD

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
    return tuple(w)


def _inv_mix_columns_word(w):
    a0, a1, a2, a3 = (w >> 24) & 0xff, (w >> 16) & 0xff, (w >> 8) & 0xff, w & 0xff
    return ((_mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9)) << 24
            | (_mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13)) << 16
            | (_mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11)) << 8
            | (_mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14)))

def _aes_encrypt_block(kw, block):
    s0, s1, s2, s3 = struct.unpack(">4I", block)
    s0 ^= kw[0]; s1 ^= kw[1]; s2 ^= kw[2]; s3 ^= kw[3]
    for rnd in range(1, 14):
        k = kw[4 * rnd:4 * rnd + 4]
        s0, s1, s2, s3 = (
            _Te0[s0 >> 24] ^ _Te1[(s1 >> 16) & 0xff] ^ _Te2[(s2 >> 8) & 0xff] ^ _Te3[s3 & 0xff] ^ k[0],
            _Te0[s1 >> 24] ^ _Te1[(s2 >> 16) & 0xff] ^ _Te2[(s3 >> 8) & 0xff] ^ _Te3[s0 & 0xff] ^ k[1],
            _Te0[s2 >> 24] ^ _Te1[(s3 >> 16) & 0xff] ^ _Te2[(s0 >> 8) & 0xff] ^ _Te3[s1 & 0xff] ^ k[2],
            _Te0[s3 >> 24] ^ _Te1[(s0 >> 16) & 0xff] ^ _Te2[(s1 >> 8) & 0xff] ^ _Te3[s2 & 0xff] ^ k[3])
    k = kw[56:60]
    s0, s1, s2, s3 = (
        (((_SBOX[s0 >> 24] << 24) | (_SBOX[(s1 >> 16) & 0xff] << 16) | (_SBOX[(s2 >> 8) & 0xff] << 8) | _SBOX[s3 & 0xff]) ^ k[0]),
        (((_SBOX[s1 >> 24] << 24) | (_SBOX[(s2 >> 16) & 0xff] << 16) | (_SBOX[(s3 >> 8) & 0xff] << 8) | _SBOX[s0 & 0xff]) ^ k[1]),
        (((_SBOX[s2 >> 24] << 24) | (_SBOX[(s3 >> 16) & 0xff] << 16) | (_SBOX[(s0 >> 8) & 0xff] << 8) | _SBOX[s1 & 0xff]) ^ k[2]),
        (((_SBOX[s3 >> 24] << 24) | (_SBOX[(s0 >> 16) & 0xff] << 16) | (_SBOX[(s1 >> 8) & 0xff] << 8) | _SBOX[s2 & 0xff]) ^ k[3]))
    return struct.pack(">4I", s0, s1, s2, s3)

_DKW_CACHE = {}

def _aes_decrypt_block(kw, block):
    # Claves de ronda 1..13 transformadas por InvMixColumns (cifrado
    # inverso equivalente); las rondas 0 y 14 se usan tal cual.
    # Se cachea por clave: calcularlo por bloque sería carísimo.
    dkw = _DKW_CACHE.get(kw)
    if dkw is None:
        dkw = tuple(kw[:4]) + tuple(_inv_mix_columns_word(w) for w in kw[4:56]) + tuple(kw[56:60])
        _DKW_CACHE[kw] = dkw
    s0, s1, s2, s3 = struct.unpack(">4I", block)
    s0 ^= kw[56]; s1 ^= kw[57]; s2 ^= kw[58]; s3 ^= kw[59]
    for rnd in range(13, 0, -1):
        k = dkw[4 * rnd:4 * rnd + 4]
        s0, s1, s2, s3 = (
            _Td0[s0 >> 24] ^ _Td1[(s3 >> 16) & 0xff] ^ _Td2[(s2 >> 8) & 0xff] ^ _Td3[s1 & 0xff] ^ k[0],
            _Td0[s1 >> 24] ^ _Td1[(s0 >> 16) & 0xff] ^ _Td2[(s3 >> 8) & 0xff] ^ _Td3[s2 & 0xff] ^ k[1],
            _Td0[s2 >> 24] ^ _Td1[(s1 >> 16) & 0xff] ^ _Td2[(s0 >> 8) & 0xff] ^ _Td3[s3 & 0xff] ^ k[2],
            _Td0[s3 >> 24] ^ _Td1[(s2 >> 16) & 0xff] ^ _Td2[(s1 >> 8) & 0xff] ^ _Td3[s0 & 0xff] ^ k[3])
    k = kw[0:4]
    s0, s1, s2, s3 = (
        (((_INV_SBOX[s0 >> 24] << 24) | (_INV_SBOX[(s3 >> 16) & 0xff] << 16) | (_INV_SBOX[(s2 >> 8) & 0xff] << 8) | _INV_SBOX[s1 & 0xff]) ^ k[0]),
        (((_INV_SBOX[s1 >> 24] << 24) | (_INV_SBOX[(s0 >> 16) & 0xff] << 16) | (_INV_SBOX[(s3 >> 8) & 0xff] << 8) | _INV_SBOX[s2 & 0xff]) ^ k[1]),
        (((_INV_SBOX[s2 >> 24] << 24) | (_INV_SBOX[(s1 >> 16) & 0xff] << 16) | (_INV_SBOX[(s0 >> 8) & 0xff] << 8) | _INV_SBOX[s3 & 0xff]) ^ k[2]),
        (((_INV_SBOX[s3 >> 24] << 24) | (_INV_SBOX[(s2 >> 16) & 0xff] << 16) | (_INV_SBOX[(s1 >> 8) & 0xff] << 8) | _INV_SBOX[s0 & 0xff]) ^ k[3]))
    return struct.pack(">4I", s0, s1, s2, s3)


def _unpad_pkcs7(data):
    if not data:
        raise ValueError("plaintext vacío")
    padding = data[-1]
    if padding < 1 or padding > 16 or data[-padding:] != bytes([padding]) * padding:
        raise ValueError("padding PKCS#7 inválido")
    return data[:-padding]


def _aes_cbc_decrypt(key, iv, ciphertext):
    """AES-256-CBC decrypt (NoobCrypt index 1/4), solo stdlib."""
    if len(iv) != 16 or len(ciphertext) % 16:
        raise ValueError("CBC con IV o longitud inválidos")
    kw = _aes_key_expand(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), 16):
        blk = ciphertext[i:i + 16]
        d = _aes_decrypt_block(kw, blk)
        out += bytes(a ^ b for a, b in zip(d, prev))
        prev = blk
    return _unpad_pkcs7(bytes(out))


def _aes_cbc_encrypt(key, iv, plaintext):
    """AES-256-CBC encrypt (solo para el round-trip de --self-test)."""
    pad = 16 - (len(plaintext) % 16)
    data = plaintext + bytes([pad]) * pad
    kw = _aes_key_expand(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        x = bytes(a ^ b for a, b in zip(blk, prev))
        e = _aes_encrypt_block(kw, x)
        out += e
        prev = e
    return bytes(out)


# ------------------------------------------------------------- AES-256-GCM
_GCM_R = 0xe1000000000000000000000000000000


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
    """AES-256-GCM decrypt (NoobCrypt index 0/3), solo stdlib. nonce: 12 bytes."""
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
    """AES-256-GCM encrypt (solo para el round-trip de --self-test)."""
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


# ------------------------------------------------------------- AES-256-XTS
def _gf128_mul_alpha(t):
    """Multiplica un tweak de 128 bits (little-endian) por x en
    GF(2^128), polinomio x^128 + x^7 + x^2 + x + 1 (IEEE 1619)."""
    n = int.from_bytes(t, "little")
    carry = (n >> 127) & 1
    n = ((n << 1) & ((1 << 128) - 1)) ^ (0x87 if carry else 0)
    return n.to_bytes(16, "little")


def _xts_tweaks(key64, tweak, nblocks):
    kw2 = _aes_key_expand(key64[32:])
    t = _aes_encrypt_block(kw2, tweak)
    tweaks = [t]
    for _ in range(nblocks):
        tweaks.append(_gf128_mul_alpha(tweaks[-1]))
    return tweaks


def _aes_xts_decrypt(key64, tweak, data):
    """AES-256-XTS decrypt (NoobCrypt index 5, IEEE 1619), solo stdlib.
    data debe tener al menos 16 bytes; el robo de texto cifrado (CTS)
    del último bloque parcial sigue el estándar: el bloque parcial
    cifrado son los primeros bytes del cifrado del último bloque
    completo, y el texto plano parcial viaja dentro de ese último
    bloque completo."""
    if len(key64) != 64 or len(tweak) != 16 or len(data) < 16:
        raise ValueError("bad XTS parameters")
    kw1 = _aes_key_expand(key64[:32])
    nblocks = len(data) // 16
    partial = len(data) % 16
    tweaks = _xts_tweaks(key64, tweak, nblocks)
    out = bytearray(len(data))
    if partial == 0:
        for i in range(nblocks):
            blk = data[i * 16:(i + 1) * 16]
            x = bytes(a ^ b for a, b in zip(blk, tweaks[i]))
            d = _aes_decrypt_block(kw1, x)
            out[i * 16:(i + 1) * 16] = bytes(a ^ b for a, b in zip(d, tweaks[i]))
        return bytes(out)
    for i in range(nblocks - 1):
        blk = data[i * 16:(i + 1) * 16]
        x = bytes(a ^ b for a, b in zip(blk, tweaks[i]))
        d = _aes_decrypt_block(kw1, x)
        out[i * 16:(i + 1) * 16] = bytes(a ^ b for a, b in zip(d, tweaks[i]))
    c_last = data[(nblocks - 1) * 16:nblocks * 16]
    c_part = data[nblocks * 16:]
    # CC_dec = D_K1(C_{n-1} XOR T_n) XOR T_n  ==  P_n || PP[partial:]
    x = bytes(a ^ b for a, b in zip(c_last, tweaks[nblocks]))
    cc_dec = _aes_decrypt_block(kw1, x)
    cc_dec = bytes(a ^ b for a, b in zip(cc_dec, tweaks[nblocks]))
    out[nblocks * 16:] = cc_dec[:partial]
    # PP = C_n || CC_dec[partial:];  P_{n-1} = D_K1(PP XOR T_{n-1}) XOR T_{n-1}
    pp = c_part + cc_dec[partial:]
    x2 = bytes(a ^ b for a, b in zip(pp, tweaks[nblocks - 1]))
    d2 = _aes_decrypt_block(kw1, x2)
    out[(nblocks - 1) * 16:nblocks * 16] = bytes(a ^ b for a, b in zip(d2, tweaks[nblocks - 1]))
    return bytes(out)


def _aes_xts_encrypt(key64, tweak, data):
    """AES-256-XTS encrypt (solo para el round-trip de --self-test)."""
    if len(key64) != 64 or len(tweak) != 16 or len(data) < 16:
        raise ValueError("bad XTS parameters")
    kw1 = _aes_key_expand(key64[:32])
    nblocks = len(data) // 16
    partial = len(data) % 16
    tweaks = _xts_tweaks(key64, tweak, nblocks)
    out = bytearray(len(data))
    if partial == 0:
        for i in range(nblocks):
            blk = data[i * 16:(i + 1) * 16]
            x = bytes(a ^ b for a, b in zip(blk, tweaks[i]))
            e = _aes_encrypt_block(kw1, x)
            out[i * 16:(i + 1) * 16] = bytes(a ^ b for a, b in zip(e, tweaks[i]))
        return bytes(out)
    for i in range(nblocks - 1):
        blk = data[i * 16:(i + 1) * 16]
        x = bytes(a ^ b for a, b in zip(blk, tweaks[i]))
        e = _aes_encrypt_block(kw1, x)
        out[i * 16:(i + 1) * 16] = bytes(a ^ b for a, b in zip(e, tweaks[i]))
    p_last = data[(nblocks - 1) * 16:nblocks * 16]
    p_part = data[nblocks * 16:]
    x = bytes(a ^ b for a, b in zip(p_last, tweaks[nblocks - 1]))
    cc = _aes_encrypt_block(kw1, x)
    cc = bytes(a ^ b for a, b in zip(cc, tweaks[nblocks - 1]))
    # C_n (parcial) = primeros bytes de CC (texto cifrado robado)
    out[nblocks * 16:] = cc[:partial]
    # C_{n-1} = E_K1((P_n || CC[partial:]) XOR T_n) XOR T_n
    combined = p_part + cc[partial:]
    x2 = bytes(a ^ b for a, b in zip(combined, tweaks[nblocks]))
    e2 = _aes_encrypt_block(kw1, x2)
    out[(nblocks - 1) * 16:nblocks * 16] = bytes(a ^ b for a, b in zip(e2, tweaks[nblocks]))
    return bytes(out)


# ------------------------------------------------------------- NoobCrypt
def _dec5(text):
    """NoobCrypt.b(text, 5, false): Base64 -> tweak[16] + ct, AES-256-XTS."""
    encoded = "".join(text.split())
    if not encoded:
        raise DecodeError("DECRYPT_FAILED", "El catálogo está vacío.")
    encoded += "=" * ((4 - len(encoded) % 4) % 4)
    try:
        raw = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise DecodeError("DECRYPT_FAILED", "El catálogo no es Base64 válido.") from exc
    if len(raw) < 32:
        raise DecodeError("DECRYPT_FAILED", "El catálogo es demasiado corto.")
    try:
        return _aes_xts_decrypt(KEY_CONFIG5, raw[:16], raw[16:])
    except ValueError as exc:
        raise DecodeError("DECRYPT_FAILED", "No se pudo descifrar el catálogo (XTS).") from exc


def _dec0(value):
    """NoobCrypt.b(value, 0, false): Base64(nonce[12] + ct + tag[16]),
    AES-256-GCM. Devuelve el texto plano o lanza ValueError."""
    encoded = "".join(value.split())
    if len(encoded) < 36:
        raise ValueError("valor demasiado corto para GCM")
    encoded += "=" * ((4 - len(encoded) % 4) % 4)
    raw = base64.b64decode(encoded, validate=True)
    if len(raw) < 28:
        raise ValueError("valor GCM demasiado corto")
    return _aes_gcm_decrypt(KEY_FIELD, raw[:12], raw[12:-16], raw[-16:]).decode("utf-8")


def _dec1(value):
    """NoobCrypt.b(value, 1, false): Base64(IV[16] + ct), AES-256-CBC.
    Devuelve el texto plano o lanza ValueError."""
    encoded = "".join(value.split())
    if len(encoded) < 24:
        raise ValueError("valor demasiado corto para CBC")
    encoded += "=" * ((4 - len(encoded) % 4) % 4)
    raw = base64.b64decode(encoded, validate=True)
    if len(raw) < 32 or (len(raw) - 16) % 16:
        raise ValueError("valor CBC con longitud inválida")
    return _aes_cbc_decrypt(KEY_FIELD, raw[:16], raw[16:]).decode("utf-8")


def _decode_value(value, index):
    """Descifra un valor de cadena con el índice NoobCrypt dado (0 o 1);
    si no descifra, devuelve el valor original (texto plano)."""
    if not isinstance(value, str) or not value:
        return value
    fn = _dec0 if index == 0 else _dec1
    try:
        return fn(value)
    except Exception:
        return value


def _decode_values(doc, index):
    if isinstance(doc, dict):
        return {k: _decode_values(v, index) for k, v in doc.items()}
    if isinstance(doc, list):
        return [_decode_values(v, index) for v in doc]
    return _decode_value(doc, index)


# ------------------------------------------------------------- JSON
def _text(data):
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return data


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
        raise DecodeError("WRONG_DOCUMENT", "Faltan las listas Servers o Tweaks del catálogo.")
    if not any(doc[k] for k in LIST_FIELDS):
        raise DecodeError("WRONG_DOCUMENT", "El catálogo no trae servidores ni tweaks.")
    # Campos de nivel superior y servidores: índice 0 (GCM).
    top = {k: v for k, v in doc.items() if k not in LIST_FIELDS}
    top = _decode_values(top, 0)
    servers = _decode_values(doc["Servers"], 0)
    # Tweaks: índice 1 (CBC); si un campo no es CBC, se prueba GCM y
    # si tampoco descifra se deja como está (p. ej. Flag "NOOB_DEV").
    tweaks = []
    for tweak in doc["Tweaks"]:
        if not isinstance(tweak, dict):
            tweaks.append(tweak)
            continue
        decoded = {}
        for k, v in tweak.items():
            if isinstance(v, str) and v:
                try:
                    decoded[k] = _dec1(v)
                except Exception:
                    decoded[k] = _decode_value(v, 0)
            elif isinstance(v, (dict, list)):
                decoded[k] = _decode_values(v, 1)
            else:
                decoded[k] = v
        tweaks.append(decoded)
    top["Servers"] = servers
    top["Tweaks"] = tweaks
    return top


def decode(data) -> dict:
    """API offline: descifra el catálogo completo y devuelve el dict.
    Acepta el cuerpo HTTP crudo (Base64, sobre XTS índice 5), o un
    JSON ya descifrado."""
    text = _text(data)
    if len(text) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El catálogo supera el tamaño máximo.")
    stripped = text.strip()
    if stripped.startswith("{"):
        return _catalog_json(stripped.encode("utf-8"))
    return _catalog_json(_dec5(stripped))


def run(file_bytes) -> str | None:
    """API offline: JSON completo del catálogo o None; nunca una lista parcial."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


# ------------------------------------------------------------- Descarga
def _https_url(url: str):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment):
        raise ValueError("invalid HTTPS URL")


def fetch_catalog(url=CATALOG_URL, timeout=8):
    """GET exactamente como la app (C2106fy.a): GET, sin cabeceras
    propias (solo el User-Agent por defecto de la plataforma), sin
    autenticación ni parámetros; connect/read timeout 8 s; exige
    HTTP 200 y devuelve el cuerpo tal cual. Si la URL no empieza por
    http:// o https://, se le antepone https://, como hace la app."""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    _https_url(url)
    req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    with urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise HTTPError(url, resp.status, "non-200", resp.headers, None)
        return resp.read()


# ------------------------------------------------------------- CLI
def _self_test():
    """Vector real (seed del APK) + round-trips XTS/GCM/CBC."""
    doc = decode(SEED_BLOB)
    assert doc["Version"] == "1.0.1", doc.get("Version")
    assert doc["DefUpdateURL"] == CATALOG_URL, doc.get("DefUpdateURL")
    assert len(doc["Servers"]) == 1, len(doc["Servers"])
    assert len(doc["Tweaks"]) == 1, len(doc["Tweaks"])
    s0 = doc["Servers"][0]
    assert s0["Name"] == "Update Config Version", s0
    assert s0["Flag"] == "fr", s0
    assert s0["ServerIPHost"] == "www.server.com", s0
    assert s0["OpenVPNUDPPort"] == "110", s0
    assert s0["Username"] == "username", s0
    t0 = doc["Tweaks"][0]
    assert t0["Name"] == "Update Config Version", t0
    assert t0["Flag"] == "NOOB_DEV", t0
    # Round-trip XTS (índice 5) con el seed real.
    raw = base64.b64decode(SEED_BLOB)
    assert _aes_xts_decrypt(KEY_CONFIG5, raw[:16], _aes_xts_encrypt(KEY_CONFIG5, raw[:16], raw[16:])) == raw[16:]
    # Round-trip GCM (índice 0) y CBC (índice 1).
    nonce = b"\x00" * 12
    ct, tag = _aes_gcm_encrypt(KEY_FIELD, nonce, b"Update Config Version")
    assert _aes_gcm_decrypt(KEY_FIELD, nonce, ct, tag) == b"Update Config Version"
    iv = b"\x01" * 16
    assert _aes_cbc_decrypt(KEY_FIELD, iv, _aes_cbc_encrypt(KEY_FIELD, iv, b"Update Config Version")) == b"Update Config Version"
    return ("self-test OK: seed version %s, %d servidor, %d tweak, "
            "round-trip XTS/GCM/CBC OK"
            % (doc["Version"], len(doc["Servers"]), len(doc["Tweaks"])))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Descifrador del catálogo de XUI Tunnel VPN (com.xui_tunnel).")
    parser.add_argument("--url", nargs="?", const=CATALOG_URL, default=None,
                        help="Descarga el catálogo de la URL (por defecto %s)." % CATALOG_URL)
    parser.add_argument("--file", default=None,
                        help="Lee el catálogo de un archivo local (sobre Base64 o JSON).")
    parser.add_argument("--self-test", action="store_true",
                        help="Verifica el descifrado con el seed real del APK.")
    parser.add_argument("-o", "--output", default=None,
                        help="Guarda el JSON descifrado en este archivo.")
    args = parser.parse_args(argv)

    if args.self_test:
        print(_self_test())
        return 0
    try:
        if args.url:
            try:
                raw = fetch_catalog(args.url)
            except Exception:
                # La app reintenta una vez con el enlace de respaldo.
                if args.url == CATALOG_URL:
                    raw = fetch_catalog(BACKUP_URL)
                else:
                    raise
        elif args.file:
            with open(args.file, "rb") as fh:
                raw = fh.read()
        else:
            parser.error("usa --url, --file o --self-test")
            return 2
        out = json.dumps(decode(raw), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError as exc:
        print("error [%s]: %s" % (exc.code, exc), file=sys.stderr)
        return 1
    except Exception as exc:  # red, tiempo agotado, HTTP 403/404...
        print("error: %s" % exc, file=sys.stderr)
        return 1
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print("guardado en %s" % args.output)
    else:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
