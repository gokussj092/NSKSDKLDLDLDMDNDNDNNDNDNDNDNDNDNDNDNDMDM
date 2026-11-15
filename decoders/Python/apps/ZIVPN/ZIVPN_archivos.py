#!/usr/bin/env python3
"""ZIVPN Tunnel - formato de archivo .ziv y XML de configuracion (SP-DECODE).

App: ZIVPN Tunnel (SSH/DNS/UDP) VPN, com.zi.zivpn, 2.2.5 (versionCode 184).

Formato .ziv (clase Lq1/a en classes3.dex):
    archivo = Base64(sal) "." Base64(iv) "." Base64(ct+tag)   [LF1/d, "secure"]
    sal = 32 bytes aleatorios; iv = 12 bytes aleatorios
    clave AES = PBKDF2-HMAC-SHA256(contrasena, sal, 1000 iter, 16 bytes)
    contrasena = "SecurePart1...SecurePart5" (45 caracteres, UTF-8)
    cifrado = AES-128-GCM, sin AAD
    capa interna = DES/ECB/PKCS5Padding, clave DESKeySpec("#ipt!2022/H")
    interior = XML de java.util.Properties ("Configuration File")

Import (Lq1/a::c):  LF1-descifra -> DES-descifra -> loadFromXML.
Export (Lq1/a::a):  XML -> LF1-cifra (SIN la capa DES: asimetria real de la
app; un archivo exportado por la 2.2.5 NO pasa el DES de su propio import,
por eso open_ziv() reintenta sin DES si el DES falla).

Validaciones del import (solo se reportan, no se imponen aqui):
file.appVersionCode == versionCode de la app; beta = fecha de expiracion;
alpha = bloqueo por root; file.askHwidLocal = HWID de la lista file.hwids.

Tambien abre:
- el XML del catalogo remoto (sin cifrar, mismo formato Properties),
- los assets zifile/zifile2 (listas Psiphon: hex de documentos JSON
  concatenados, 225 + 41 servidores).

Uso:
    python3 ZIVPN_archivos.py --file ejemplo.ziv
    python3 ZIVPN_archivos.py --file catalogo.xml
    python3 ZIVPN_archivos.py --seal props.json --out ejemplo.ziv
    python3 ZIVPN_archivos.py --self-test
"""
import argparse
import base64
import binascii
import hashlib
import json
import os
import struct
import sys
import xml.etree.ElementTree as ET

LF1_PASSWORD = "SecurePart1SecurePart2SecurePart3SecurePart4SecurePart5"
DES_KEY = b"#ipt!2022/H"
SALT_LEN = 32
IV_LEN = 12
PBKDF2_ITERS = 1000
KEY_LEN = 16  # AES-128

TUNNEL_TYPES = {
    1: "sshProxy", 2: "sshSslTunnel", 3: "udptunnel", 4: "psiphontunnel",
    5: "v2raytunnel", 6: "litevpntunnel", 7: "sshDirect",
}
TUNNEL_TYPE_IDS = {v: k for k, v in TUNNEL_TYPES.items()}


class DecodeError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------- AES (stdlib)
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


def _aes_key_expand(key):
    nk = len(key) // 4
    nr = nk + 6
    w = list(struct.unpack(">%dI" % nk, key))
    for i in range(nk, 4 * (nr + 1)):
        temp = w[i - 1]
        if i % nk == 0:
            rot = ((temp << 8) | (temp >> 24)) & 0xffffffff
            sub = (_SBOX[(rot >> 24) & 0xff] << 24) | (_SBOX[(rot >> 16) & 0xff] << 16) \
                | (_SBOX[(rot >> 8) & 0xff] << 8) | _SBOX[rot & 0xff]
            temp = sub ^ (_RCON[i // nk - 1] << 24)
        elif nk > 6 and i % nk == 4:
            temp = (_SBOX[(temp >> 24) & 0xff] << 24) | (_SBOX[(temp >> 16) & 0xff] << 16) \
                | (_SBOX[(temp >> 8) & 0xff] << 8) | _SBOX[temp & 0xff]
        w.append(w[i - nk] ^ temp)
    return w, nr


def _xtime(x):
    return ((x << 1) ^ (0x1b if x & 0x80 else 0)) & 0xff


def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


def _aes_encrypt_block(key_words, nr, block):
    s = list(struct.unpack(">4I", block))
    rk = key_words
    for i in range(4):
        s[i] ^= rk[i]
    for rnd in range(1, nr):
        b = bytearray(16)
        for i in range(4):
            for j in range(4):
                b[4 * j + i] = _SBOX[(s[j] >> (24 - 8 * i)) & 0xff]
        sb = bytearray(16)
        for r in range(4):
            for c in range(4):
                sb[4 * c + r] = b[4 * ((c + r) % 4) + r]
        out = [0] * 4
        for c in range(4):
            a0, a1, a2, a3 = sb[4 * c], sb[4 * c + 1], sb[4 * c + 2], sb[4 * c + 3]
            out[c] = (_xtime(a0) ^ (_xtime(a1) ^ a1) ^ a2 ^ a3) << 24 \
                | (a0 ^ _xtime(a1) ^ (_xtime(a2) ^ a2) ^ a3) << 16 \
                | (a0 ^ a1 ^ _xtime(a2) ^ (_xtime(a3) ^ a3)) << 8 \
                | ((_xtime(a0) ^ a0) ^ a1 ^ a2 ^ _xtime(a3))
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
        s[i] ^= rk[4 * nr + i]
    return struct.pack(">4I", *s)


def _aes_decrypt_block(key_words, nr, block):
    s = list(struct.unpack(">4I", block))
    rk = key_words
    for i in range(4):
        s[i] ^= rk[4 * nr + i]
    for rnd in range(nr - 1, 0, -1):
        b = bytearray(16)
        for i in range(4):
            for j in range(4):
                b[4 * j + i] = _INV_SBOX[(s[j] >> (24 - 8 * i)) & 0xff]
        sb = bytearray(16)
        for r in range(4):
            for c in range(4):
                sb[4 * c + r] = b[4 * ((c - r) % 4) + r]
        s = list(struct.unpack(">4I", bytes(sb)))
        for i in range(4):
            s[i] ^= rk[4 * rnd + i]
        out = [0] * 4
        for c in range(4):
            a0 = (s[c] >> 24) & 0xff
            a1 = (s[c] >> 16) & 0xff
            a2 = (s[c] >> 8) & 0xff
            a3 = s[c] & 0xff
            out[c] = (_gmul(a0, 14) ^ _gmul(a1, 11) ^ _gmul(a2, 13) ^ _gmul(a3, 9)) << 24 \
                | (_gmul(a0, 9) ^ _gmul(a1, 14) ^ _gmul(a2, 11) ^ _gmul(a3, 13)) << 16 \
                | (_gmul(a0, 13) ^ _gmul(a1, 9) ^ _gmul(a2, 14) ^ _gmul(a3, 11)) << 8 \
                | (_gmul(a0, 11) ^ _gmul(a1, 13) ^ _gmul(a2, 9) ^ _gmul(a3, 14))
        s = out
    b = bytearray(16)
    for i in range(4):
        for j in range(4):
            b[4 * j + i] = _INV_SBOX[(s[j] >> (24 - 8 * i)) & 0xff]
    sb = bytearray(16)
    for r in range(4):
        for c in range(4):
            sb[4 * c + r] = b[4 * ((c - r) % 4) + r]
    s = list(struct.unpack(">4I", bytes(sb)))
    for i in range(4):
        s[i] ^= rk[i]
    return struct.pack(">4I", *s)


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
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    kw, nr = _aes_key_expand(key)
    h = int.from_bytes(_aes_encrypt_block(kw, nr, b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    pt = bytearray()
    counter = 1
    for i in range(0, len(ciphertext), 16):
        chunk = ciphertext[i:i + 16]
        ctr = nonce + struct.pack(">I", counter + 1)
        ks = _aes_encrypt_block(kw, nr, ctr)
        pt += bytes(a ^ b for a, b in zip(chunk, ks))
        counter += 1

    def pad16(d):
        return d + b"\x00" * ((-len(d)) % 16)
    s = _ghash(h, pad16(aad) + pad16(ciphertext)
               + struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8))
    ej0 = _aes_encrypt_block(kw, nr, j0)
    calc_tag = (s ^ int.from_bytes(ej0, "big")).to_bytes(16, "big")
    if calc_tag != tag:
        raise ValueError("GCM tag mismatch")
    return bytes(pt)


def _aes_gcm_encrypt(key, nonce, plaintext, aad=b""):
    kw, nr = _aes_key_expand(key)
    h = int.from_bytes(_aes_encrypt_block(kw, nr, b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    ct = bytearray()
    counter = 1
    for i in range(0, len(plaintext), 16):
        chunk = plaintext[i:i + 16]
        ctr = nonce + struct.pack(">I", counter + 1)
        ks = _aes_encrypt_block(kw, nr, ctr)
        ct += bytes(a ^ b for a, b in zip(chunk, ks))
        counter += 1

    def pad16(d):
        return d + b"\x00" * ((-len(d)) % 16)
    s = _ghash(h, pad16(aad) + pad16(bytes(ct))
               + struct.pack(">QQ", len(aad) * 8, len(ct) * 8))
    ej0 = _aes_encrypt_block(kw, nr, j0)
    tag = (s ^ int.from_bytes(ej0, "big")).to_bytes(16, "big")
    return bytes(ct), tag


# ------------------------------------------------------------- DES (stdlib)
_IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
       62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
       57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
       61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
_FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
       38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
       36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
       34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
_E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
      12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
      24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
_P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
      2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
_PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
        59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39,
        31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
        29, 21, 13, 5, 28, 20, 12, 4]
_PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
_ROT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
_SBOXES = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]


def _permute(block, table, nbits):
    out = 0
    for i, pos in enumerate(table):
        bit = (block >> (nbits - pos)) & 1
        out |= bit << (len(table) - 1 - i)
    return out


def _des_subkeys(key8):
    k = int.from_bytes(key8, "big")
    pc1 = _permute(k, _PC1, 64)
    c = (pc1 >> 28) & 0xfffffff
    d = pc1 & 0xfffffff
    subkeys = []
    for r in _ROT:
        c = ((c << r) | (c >> (28 - r))) & 0xfffffff
        d = ((d << r) | (d >> (28 - r))) & 0xfffffff
        subkeys.append(_permute((c << 28) | d, _PC2, 56))
    return subkeys


def _des_f(r32, subkey):
    e = _permute(r32, _E, 32)
    x = e ^ subkey
    out = 0
    for i in range(8):
        chunk = (x >> (42 - 6 * i)) & 0x3f
        row = ((chunk >> 5) & 1) * 2 + (chunk & 1)
        col = (chunk >> 1) & 0xf
        out = (out << 4) | _SBOXES[i][row * 16 + col]
    return _permute(out, _P, 32)


def _des_block(key8, block8, decrypt=False):
    subkeys = _des_subkeys(key8)
    if decrypt:
        subkeys = subkeys[::-1]
    b = int.from_bytes(block8, "big")
    ip = _permute(b, _IP, 64)
    left = (ip >> 32) & 0xffffffff
    right = ip & 0xffffffff
    for sk in subkeys:
        left, right = right, left ^ _des_f(right, sk)
    pre = (right << 32) | left
    return _permute(pre, _FP, 64).to_bytes(8, "big")


def _des_ecb(data, decrypt=False):
    if len(data) % 8:
        raise DecodeError("DES_LENGTH", "Los datos DES no son multiplo de 8.")
    key8 = DES_KEY[:8]
    out = bytearray()
    for i in range(0, len(data), 8):
        out += _des_block(key8, data[i:i + 8], decrypt=decrypt)
    return bytes(out)


def _pkcs5_pad(data):
    pad = 8 - (len(data) % 8)
    return data + bytes([pad]) * pad


def _pkcs5_unpad(data):
    if not data:
        raise DecodeError("BAD_PADDING", "Texto vacio tras DES.")
    pad = data[-1]
    if pad < 1 or pad > 8 or data[-pad:] != bytes([pad]) * pad:
        raise DecodeError("BAD_PADDING", "Padding PKCS5 invalido.")
    return data[:-pad]


# ------------------------------------------------------------- LF1 (secure)
def _lf1_key(salt):
    return hashlib.pbkdf2_hmac("sha256", LF1_PASSWORD.encode("utf-8"),
                               salt, PBKDF2_ITERS, dklen=KEY_LEN)


def lf1_decrypt(text):
    """'b64(sal).b64(iv).b64(ct+tag)' -> bytes (AES-128-GCM)."""
    parts = text.strip().split(".")
    if len(parts) != 3:
        raise DecodeError("LF1_FORMAT", "El .ziv no tiene 3 partes separadas por '.'.")
    try:
        salt = base64.b64decode(parts[0])
        iv = base64.b64decode(parts[1])
        cttag = base64.b64decode(parts[2])
    except (binascii.Error, ValueError) as exc:
        raise DecodeError("LF1_BASE64", "Una parte del .ziv no es Base64.") from exc
    if len(salt) != SALT_LEN or len(iv) != IV_LEN or len(cttag) < 16:
        raise DecodeError("LF1_LENGTH", "Longitudes de sal/iv/cifrado invalidas.")
    key = _lf1_key(salt)
    try:
        return _aes_gcm_decrypt(key, iv, cttag[:-16], cttag[-16:])
    except ValueError as exc:
        raise DecodeError("LF1_TAG", "El tag GCM del .ziv no verifica.") from exc


def lf1_encrypt(data, salt=None, iv=None):
    """bytes -> 'b64(sal).b64(iv).b64(ct+tag)' (sal/iv aleatorios si no se dan)."""
    if salt is None:
        salt = os.urandom(SALT_LEN)
    if iv is None:
        iv = os.urandom(IV_LEN)
    key = _lf1_key(salt)
    ct, tag = _aes_gcm_encrypt(key, iv, data)
    return ".".join((
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(iv).decode("ascii"),
        base64.b64encode(ct + tag).decode("ascii"),
    ))


# ------------------------------------------------------------- .ziv / XML
def parse_properties_xml(xml_bytes):
    try:
        text = xml_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecodeError("BAD_UTF8", "El interior del .ziv no es UTF-8.") from exc
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise DecodeError("BAD_XML", "El XML de propiedades no parsea.") from exc
    props = {}
    for entry in root.findall("entry"):
        key = entry.get("key")
        if key is not None:
            props[key] = entry.text or ""
    return props, text


def properties_xml(props):
    """dict -> bytes XML de java.util.Properties (mismo formato de la app)."""
    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd">',
             '<properties>',
             '<comment>Configuration File</comment>']
    for key in sorted(props):
        val = props[key]
        esc = (val.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
        lines.append('<entry key="%s">%s</entry>' % (key, esc))
    lines.append('</properties>')
    return ("\n".join(lines) + "\n").encode("utf-8")


def open_ziv(data):
    """Abre un .ziv (bytes o str) -> (props, xml_text, info).

    info['des_layer']: True si la capa DES estaba presente (formato que el
    import espera), False si el archivo era solo LF1 (lo que exporta la app).
    """
    if isinstance(data, bytes):
        text = data.decode("utf-8", errors="strict")
    else:
        text = data
    inner = lf1_decrypt(text)
    try:
        xml_bytes = _pkcs5_unpad(_des_ecb(inner, decrypt=True))
        des_layer = True
    except DecodeError:
        # Archivo exportado por la app (solo LF1, sin DES): usarlo directo.
        xml_bytes = inner
        des_layer = False
    props, xml_text = parse_properties_xml(xml_bytes)
    return props, xml_text, {"des_layer": des_layer}


def open_plain_xml(data):
    """XML de configuracion sin cifrar (catalogo remoto, etc.)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    props, xml_text = parse_properties_xml(data)
    return props, xml_text, {"des_layer": False}


def seal_ziv(props, legacy=True, salt=None, iv=None):
    """dict de propiedades -> texto .ziv.

    legacy=True (default): XML -> DES cifra -> LF1 cifra. Es el formato que
    el import de la app (Lq1/a::c) espera.
    legacy=False: XML -> LF1 cifra. Es lo que exporta la app (Lq1/a::a).
    """
    xml_bytes = properties_xml(props)
    inner = _des_ecb(_pkcs5_pad(xml_bytes), decrypt=False) if legacy else xml_bytes
    return lf1_encrypt(inner, salt=salt, iv=iv)


def decode_zifile(data):
    """Asset zifile/zifile2: hex de documentos JSON concatenados -> lista."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    hx = bytes(b for b in data if b not in b" \t\r\n")
    try:
        raw = binascii.unhexlify(hx).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise DecodeError("ZIFILE_HEX", "El asset no es hex valido.") from exc
    dec = json.JSONDecoder()
    docs, idx = [], 0
    while idx < len(raw):
        while idx < len(raw) and raw[idx] in " \t\r\n":
            idx += 1
        if idx >= len(raw):
            break
        obj, end = dec.raw_decode(raw, idx)
        docs.append(obj)
        idx = end
    if not docs:
        raise DecodeError("ZIFILE_EMPTY", "El asset no contiene documentos JSON.")
    return docs


def describe(props):
    tt = props.get("tunnelType", "")
    try:
        tt_i = int(tt)
    except ValueError:
        tt_i = None
    return {
        "tunnelType": TUNNEL_TYPES.get(tt_i, tt or "?"),
        "server": props.get("udpserver") or props.get("sshServer") or props.get("litehost") or "",
        "appVersionCode": props.get("file.appVersionCode", ""),
        "askLogin": props.get("file.askLogin", ""),
        "askHwid": props.get("file.askHwid", ""),
        "askHwidLocal": props.get("file.askHwidLocal", ""),
        "alpha": props.get("alpha", ""),
        "beta": props.get("beta", ""),
        "gamma": props.get("gamma", ""),
        "msg": props.get("file.msg", ""),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="ZIVPN Tunnel - archivos .ziv / XML")
    ap.add_argument("--file", help="Archivo .ziv, XML o asset zifile")
    ap.add_argument("--seal", help="JSON de propiedades para sellar un .ziv")
    ap.add_argument("--out", help="Archivo de salida para --seal")
    ap.add_argument("--legacy", action="store_true", default=True,
                    help="Sellar con capa DES (formato del import, default)")
    ap.add_argument("--export-style", action="store_true",
                    help="Sellar solo LF1 (como exporta la app)")
    ap.add_argument("--self-test", action="store_true", help="Pruebas internas")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()
    if args.seal:
        with open(args.seal, "r", encoding="utf-8") as fh:
            props = json.load(fh)
        text = seal_ziv(props, legacy=not args.export_style)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text)
        print(text)
        return 0
    if not args.file:
        ap.error("usa --file o --seal")
    with open(args.file, "rb") as fh:
        data = fh.read()
    if data.lstrip().startswith(b"<?xml"):
        props, xml_text, info = open_plain_xml(data)
        kind = "xml"
    elif data[:1] in (b"{", b" ") or b"7b22" in data[:64]:
        docs = decode_zifile(data)
        print(json.dumps({"kind": "zifile", "documents": len(docs),
                          "regions": sorted({d.get("region") for d in docs if isinstance(d, dict)})},
                         ensure_ascii=False, indent=2))
        return 0
    else:
        props, xml_text, info = open_ziv(data)
        kind = "ziv"
    result = {"kind": kind, "properties": props, "describe": describe(props), "info": info}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def _self_test():
    # 1) Vectores conocidos: DES (FIPS 46-3) y AES-128 (FIPS 197).
    assert _des_block(bytes.fromhex("133457799BBCDFF1"),
                      bytes.fromhex("0123456789ABCDEF")).hex() == "85e813540f0ab405"
    assert _des_block(bytes.fromhex("133457799BBCDFF1"),
                      bytes.fromhex("85E813540F0AB405"), decrypt=True).hex() == "0123456789abcdef"
    kw, nr = _aes_key_expand(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    assert _aes_encrypt_block(kw, nr, bytes.fromhex("00112233445566778899aabbccddeeff")).hex() \
        == "69c4e0d86a7b0430d8cdb78070b4c55a"
    assert _aes_decrypt_block(kw, nr, bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")).hex() \
        == "00112233445566778899aabbccddeeff"
    # 2) Vector .ziv congelado (sellado legacy con sal/iv fijos).
    props, _xml, info = open_ziv(_GOLDEN_ZIV)
    assert info["des_layer"] is True
    assert props.get("tunnelType") == "4", props.get("tunnelType")
    assert props.get("udpserver") == "udpsg1.zivpn.com", props.get("udpserver")
    assert props.get("sshPortaLocal") == "1080"
    # 3) Round-trip legacy y export-style.
    sample = {"tunnelType": "4", "udpserver": "udpsg1.zivpn.com",
              "sshPortaLocal": "1080", "file.appVersionCode": "24",
              "file.askLogin": "0", "alpha": "0", "beta": "0", "gamma": "0"}
    for legacy in (True, False):
        sealed = seal_ziv(sample, legacy=legacy)
        back, _x, info2 = open_ziv(sealed)
        assert info2["des_layer"] is legacy, (legacy, info2)
        for k, v in sample.items():
            assert back.get(k) == v, (k, back.get(k))
    # 4) XML plano (catalogo remoto) y zifile.
    props2, _x2, _i2 = open_plain_xml(_GOLDEN_XML.encode("utf-8"))
    assert props2.get("udpserver") == "udpsg1.zivpn.com"
    docs = decode_zifile(_GOLDEN_ZIFILE)
    assert len(docs) == 1 and docs[0].get("region") == "US"
    print("self-test OK: DES/AES vectores, .ziv dorado, round-trips, XML, zifile")
    return 0


_GOLDEN_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd">
<properties>
<comment>Configuration File</comment>
<entry key="sshPortaLocal">1080</entry>
<entry key="file.askLogin">0</entry>
<entry key="tunnelType">4</entry>
<entry key="file.appVersionCode">24</entry>
<entry key="udpserver">udpsg1.zivpn.com</entry>
<entry key="alpha">0</entry>
<entry key="beta">0</entry>
<entry key="gamma">0</entry>
</properties>
"""

_GOLDEN_ZIFILE = "20202020200d0a7b22726567696f6e223a20225553222c2022697041646472657373223a202231302e302e302e31227d"

_GOLDEN_ZIV = (
    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=.AAECAwQFBgcICQoL.BmeBN32POHChVE6lvsdBI+BgR/m/6AedxbjWktk/oP3ZrarNA99NfFQXMc3Y/P2/ySJzVbqzMmUDy6vFwcod9lH/1GrV4esvS8d169YrXtiPNon3I85X+sH6pc+2HhQ8C3y3752TFkp1F6xEpNWK5UgqXGlMcXO0z2zoPsnrAjuoWkCyEu4cvLzqzf0aoI1XKR6R3fnqJzHV3sCFqSwblpWkCDdXsviEyCVEoz/WySdrJJiMbyEK+uFFPtqiX5VncE++54GX8A+XTzHBNat2xqEdmC0+Y8PcYgUnsVDWShuvVcoyK/DNtgRJsdgI0sLDAfFqcz67X2LCioiIhKw7gXcdmLo6/ZJ8wVH3cT2dss9kGXvGVq5q2xJ/Drhqnbiyq+20ijkpbSuJ3tHGZSfdIwQki34A1TAwJdPybSN/NuFcQT/GaNndDS39/pREmp7qrAhDf5Sde07p2OpXzfluVkNYz9PpVjhT4MQ46jYJxyCevGlmDx/h/0AqDrJ+99nKFM8P9ueSEkjsyR4+ZNM+frwsp6tdPlufTu4TWecpCiqZWODS9RKNxGGIDB0795eBl8OI4xsvbAyK4VFjhR6HxUs7d9MLB/mmrA+MOgaFO9Thbqef5RQZ3efcCykNx9kT"
)


if __name__ == "__main__":
    sys.exit(main())
