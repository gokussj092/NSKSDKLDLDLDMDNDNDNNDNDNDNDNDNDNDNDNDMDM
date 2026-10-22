#!/usr/bin/env python3
"""SP-DECODE bot: standalone RENZ / 7NET family decoder.

The cryptographic profiles and transforms are extracted from the user-provided
66.py source. No Telegram/network dependencies or calls to remote URLs.
Supports file configurations and textual schemes through a single engine.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import struct
import sys
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

MAX_INPUT_BYTES = 2 * 1024 * 1024

# ========== RENZ Constants ==========
RENZ_FIXED_SALT = bytes.fromhex("70ed508428ff7b5bcde0bcdd3b9474932ab1cabc5ff6870e6e584b4fa7925f55")
RENZ_BASE_MATERIAL = bytes.fromhex("deb72221be4652c347f930e85adc29970ccd499cf42e361b3d6b14918912bf3b")
RENZ_FIXED_IV = bytes.fromhex("2d2f3112a271edbba9a41ad58a3a99bf")
RENZ_MASK64 = 0xFFFFFFFFFFFFFFFF
RENZ_DELTA = 0x7A56D3E1
RENZ_THREEFISH_C240 = 0x1BD11BDAA9FC1A22
RENZ_THREEFISH256_ROTATIONS = ((14,16),(52,57),(23,40),(5,37),(25,33),(46,12),(58,22),(32,32))
RENZ_THREEFISH256_PERMUTE = (0,3,2,1)
RENZ_THREEFISH256_INV_PERMUTE = (0,3,2,1)
RENZ_SHA256_KEY_16 = hashlib.sha256(RENZ_BASE_MATERIAL).digest()[:16]

try:
    import skein
    RENZ_SKEIN_OK = True
except ImportError:
    RENZ_SKEIN_OK = False

class RENZError(Exception):
    pass

# ========== دوال مساعدة ==========
def renz_pkcs7_unpad(data: bytes) -> bytes:
    if not data: raise RENZError("empty")
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad])*pad:
        raise RENZError("bad padding")
    return data[:-pad]

def renz_hkdf_sha256(ikm: bytes, salt: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    prev = b""
    c = 1
    while len(out) < length:
        prev = hmac.new(prk, prev + bytes([c]), hashlib.sha256).digest()
        out += prev
        c += 1
    return out[:length]

def renz_pbkdf2_sha256(pwd: bytes, salt: bytes, it: int = 100000, dklen: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", pwd, salt, it, dklen)

def renz_clean_base64(text: str) -> str:
    cleaned = re.sub(r'[^A-Za-z0-9+/=]', '', text)
    if len(cleaned) % 4:
        cleaned += '=' * (4 - len(cleaned) % 4)
    return cleaned

def renz_base64_decode_android(text: str) -> bytes:
    s = renz_clean_base64(text)
    if not s:
        return b""
    try:
        return base64.b64decode(s, validate=False)
    except Exception as e:
        raise RENZError(f"b64 fail: {e}")

def renz_bytes_to_text(b: bytes) -> str | None:
    try:
        return b.decode("utf-8")
    except:
        return None

def renz_strip_scheme(text: str) -> str:
    protocols = [
        '7net://', '7netvpn://', 'tcx://', 'tcxtunnelplus://',
        'ihome://', 'ihomevpn://', 'xhypher://', 'xhyphertunnelpro://',
        'izph://', 'izphvpnpro://', 'osp://', 'osptunnel://',
        'actunnelvpn://', '.actun://', 'bshieldnet://', 'bshield://',
        'safetunnel://', 'mhrtunnel://', 'letsvpngo://',
        'aloplusvpn://', 'cranetunnel://', 'vipsnipherpro://',
        'deshtunnelvpn://', 'hamotunnelplus://', 'gcpvpn://'
    ]
    for proto in protocols:
        if text.startswith(proto):
            return text.split(proto, 1)[-1]
    return text.strip()

# ========== XXTEA و Threefish ==========
def renz_ror64(v: int, c: int) -> int:
    return ((v >> c) | (v << (64 - c))) & RENZ_MASK64

def renz_xxtea_to_uint32(data: bytes, incl_len: bool) -> list:
    wc = (len(data)+3)//4
    res = [0]*(wc + (1 if incl_len else 0))
    for i,b in enumerate(data):
        res[i>>2] |= b << ((i&3)<<3)
    if incl_len:
        res[wc] = len(data)
    return res

def renz_xxtea_to_bytes(words: list, incl_len: bool) -> bytes:
    sz = len(words)*4
    if incl_len:
        real = words[-1]
        if real < sz-7 or real > sz-4:
            raise RENZError("bad xxtea len")
        sz = real
    out = bytearray(sz)
    for i in range(sz):
        out[i] = (words[i>>2] >> ((i&3)<<3)) & 0xFF
    return bytes(out)

def renz_xxtea_decrypt(data: bytes, key_mat: bytes) -> bytes:
    if not data:
        return b""
    v = renz_xxtea_to_uint32(data, False)
    k = renz_xxtea_to_uint32(key_mat[:16].ljust(16,b'\x00'), False)
    n = len(v)
    if n < 2:
        return data
    rounds = 6 + 52//n
    total = (rounds * RENZ_DELTA) & 0xFFFFFFFF
    while total:
        e = (total>>2) & 3
        y = v[0]
        for p in range(n-1,0,-1):
            z = v[p-1]
            mx = ((((z>>5)^((y<<2)&0xFFFFFFFF)) + ((y>>3)^((z<<4)&0xFFFFFFFF))) ^ ((total^y) + (k[(p&3)^e]^z)))
            v[p] = (v[p] - mx) & 0xFFFFFFFF
            y = v[p]
        z = v[n-1]
        mx = ((((z>>5)^((y<<2)&0xFFFFFFFF)) + ((y>>3)^((z<<4)&0xFFFFFFFF))) ^ ((total^y) + (k[e]^z)))
        v[0] = (v[0] - mx) & 0xFFFFFFFF
        total = (total - RENZ_DELTA) & 0xFFFFFFFF
    return renz_xxtea_to_bytes(v, True)

def renz_threefish256_subkeys(kw: list, tw: tuple) -> list:
    keys = kw + [RENZ_THREEFISH_C240 ^ kw[0] ^ kw[1] ^ kw[2] ^ kw[3]]
    tws = [tw[0], tw[1], tw[0]^tw[1]]
    sub = []
    for i in range(19):
        sub.append([
            keys[i%5],
            (keys[(i+1)%5] + tws[i%3]) & RENZ_MASK64,
            (keys[(i+2)%5] + tws[(i+1)%3]) & RENZ_MASK64,
            (keys[(i+3)%5] + i) & RENZ_MASK64
        ])
    return sub

def renz_threefish256_mix_inv(y0,y1,rot):
    x1 = renz_ror64(y0 ^ y1, rot)
    x0 = (y0 - x1) & RENZ_MASK64
    return x0,x1

def renz_threefish256_decrypt_block(block, key, tweak):
    state = block[:]
    sub = renz_threefish256_subkeys(key, tweak)
    for grp in range(17,-1,-1):
        ak = sub[grp+1]
        for i in range(4):
            state[i] = (state[i] - ak[i]) & RENZ_MASK64
        for step in range(3,-1,-1):
            state = [state[RENZ_THREEFISH256_INV_PERMUTE[i]] for i in range(4)]
            rot = RENZ_THREEFISH256_ROTATIONS[(grp*4+step)%8]
            state[0],state[1] = renz_threefish256_mix_inv(state[0],state[1], rot[0])
            state[2],state[3] = renz_threefish256_mix_inv(state[2],state[3], rot[1])
    ak = sub[0]
    for i in range(4):
        state[i] = (state[i] - ak[i]) & RENZ_MASK64
    return state

def threefish_set_key(block_bits: int, key_words: list, tweak: list) -> list:
    """
    Compute the 19 round subkeys for Threefish-256.
    Standalone version used by renz.py's decrypt_speciale.
    """
    kw = key_words[:4]
    ks4 = RENZ_THREEFISH_C240 ^ kw[0] ^ kw[1] ^ kw[2] ^ kw[3]
    keys = kw + [ks4]
    t0, t1 = tweak[0] & RENZ_MASK64, tweak[1] & RENZ_MASK64
    tws = [t0, t1, (t0 ^ t1) & RENZ_MASK64]
    subkeys = []
    for s in range(19):
        subkeys.append([
            keys[s % 5] & RENZ_MASK64,
            (keys[(s + 1) % 5] + tws[s % 3]) & RENZ_MASK64,
            (keys[(s + 2) % 5] + tws[(s + 1) % 3]) & RENZ_MASK64,
            (keys[(s + 3) % 5] + s) & RENZ_MASK64,
        ])
    return subkeys

def threefish_decrypt256_block(subkeys: list, cipher_words: list, out_words: list):
    """
    Decrypt a single Threefish-256 block.
    Standalone version used by renz.py's decrypt_speciale.
    Writes plaintext into out_words in-place.
    """
    state = list(cipher_words[:4])
    for grp in range(17, -1, -1):
        ak = subkeys[grp + 1]
        for i in range(4):
            state[i] = (state[i] - ak[i]) & RENZ_MASK64
        for step in range(3, -1, -1):
            state = [state[RENZ_THREEFISH256_INV_PERMUTE[i]] for i in range(4)]
            rot = RENZ_THREEFISH256_ROTATIONS[(grp * 4 + step) % 8]
            state[0], state[1] = renz_threefish256_mix_inv(state[0], state[1], rot[0])
            state[2], state[3] = renz_threefish256_mix_inv(state[2], state[3], rot[1])
    ak = subkeys[0]
    for i in range(4):
        state[i] = (state[i] - ak[i]) & RENZ_MASK64
    for i in range(4):
        out_words[i] = state[i]

def renz_threefish256_decrypt(data: bytes, key_mat: bytes) -> bytes:
    if not RENZ_SKEIN_OK:
        raise RENZError("pyskein missing")
    if len(data)%32 != 0:
        raise RENZError("bad threefish len")
    out = bytearray()
    for idx in range(0,len(data),32):
        tweak = struct.pack("<QQ", idx//32, 0)
        cipher = skein.threefish(key_mat, tweak)
        out.extend(cipher.decrypt_block(data[idx:idx+32]))
    return bytes(out)

# ========== AES CBC ==========
def renz_aes128_cbc_fixed(ct: bytes, key16: bytes) -> bytes:
    if len(ct)%16 != 0:
        raise RENZError("bad aes len")
    cipher = AES.new(key16, AES.MODE_CBC, RENZ_FIXED_IV)
    return renz_pkcs7_unpad(cipher.decrypt(ct))

def renz_aes256_cbc_prefixed_iv(ct: bytes, key32: bytes) -> bytes:
    if len(ct) < 16:
        raise RENZError("no iv")
    iv, body = ct[:16], ct[16:]
    if len(body)%16 != 0:
        raise RENZError("bad body len")
    cipher = AES.new(key32, AES.MODE_CBC, iv)
    return renz_pkcs7_unpad(cipher.decrypt(body))


# ========== STANDALONE RENZ DECRYPTION (from renz.py) ==========

RENZ_KEYS = {
    "bshield": {
        "KEY_SEED": bytes([
            0x60, 0x61, 0x92, 0x46, 0x60, 0x4A, 0xE9, 0xC8,
            0xCE, 0x17, 0xAF, 0x5E, 0x8B, 0x27, 0x1E, 0xC8,
            0x28, 0x92, 0xE3, 0x21, 0xF6, 0xEF, 0x99, 0x6D,
            0x10, 0xF2, 0x1B, 0x95, 0x35, 0xA3, 0x9F, 0x9D,
        ]),
        "IV": bytes([
            0x5B, 0xEF, 0xAD, 0x07, 0xD4, 0xF0, 0xC0, 0x8B,
            0x21, 0xBE, 0x7D, 0x81, 0x79, 0xD8, 0x09, 0x66,
        ]),
        "FIXED_SALT": bytes([
            0x0E, 0x83, 0xB2, 0xAE, 0x50, 0xB6, 0x15, 0x47, 0xE1,
            0xD5, 0x20, 0x24, 0xAB, 0x22, 0x6A, 0xC9, 0xD2, 0xC0,
            0xC1, 0xF8, 0x51, 0xBB, 0x1A, 0x62, 0xB3, 0x03, 0xB4,
            0xB8, 0xC9, 0x7A, 0xF4, 0x6D
        ]),
        "URL": "https://raw.githubusercontent.com/snapb/B-SHIELD-NET-2026/refs/heads/main/b_shield_net_2026"
    },
    "izph": {
        "KEY_SEED": bytes([
            0x89, 0x68, 0xCB, 0x6E, 0x89, 0x51, 0x05, 0xBE,
            0x62, 0x58, 0x39, 0xAD, 0x9B, 0x9B, 0xA6, 0xAC,
            0xE8, 0xDC, 0xD4, 0x41, 0x3D, 0x7C, 0x5E, 0xCF,
            0xAA, 0x10, 0x69, 0x41, 0x3F, 0xFE, 0xB0, 0x44
        ]),
        "FIXED_SALT": bytes([
            0xC2, 0x7F, 0xD7, 0xBE, 0xE1, 0x71, 0x96, 0xD6, 0x50,
            0x53, 0x08, 0x86, 0xCF, 0x4C, 0x24, 0xF5, 0x2C, 0xAC,
            0x5A, 0xBB, 0x8B, 0xFF, 0x6A, 0xD3, 0xA4, 0x8E, 0xBB,
            0x10, 0xF4, 0xB1, 0xF6, 0x32
        ]),
        "IV": bytes([
            0x49, 0xE5, 0x9F, 0xDF, 0x67, 0xEB, 0x47, 0x9C,
            0xE8, 0xB9, 0x6C, 0x24, 0xD2, 0x49, 0x5B, 0xD1
        ]),
        "URL": "https://raw.githubusercontent.com/kiranoble/config/refs/heads/main/izph49"
    },
    "7net": {
        "KEY_SEED": bytes([
            0xDE, 0xB7, 0x22, 0x21, 0xBE, 0x46, 0x52, 0xC3, 0x47,
            0xF9, 0x30, 0xE8, 0x5A, 0xDC, 0x29, 0x97, 0x0C, 0xCD,
            0x49, 0x9C, 0xF4, 0x2E, 0x36, 0x1B, 0x3D, 0x6B, 0x14,
            0x91, 0x89, 0x12, 0xBF, 0x3B
        ]),
        "IV": bytes([
            0x2D, 0x2F, 0x31, 0x12, 0xA2, 0x71, 0xED, 0xBB,
            0xA9, 0xA4, 0x1A, 0xD5, 0x8A, 0x3A, 0x99, 0xBF
        ]),
        "FIXED_SALT": bytes([
            0x70, 0xED, 0x50, 0x84, 0x28, 0xFF, 0x7B, 0x5B, 0xCD,
            0xE0, 0xBC, 0xDD, 0x3B, 0x94, 0x74, 0x93, 0x2A, 0xB1,
            0xCA, 0xBC, 0x5F, 0xF6, 0x87, 0x0E, 0x6E, 0x58, 0x4B,
            0x4F, 0xA7, 0x92, 0x5F, 0x55
        ]),
        "URL": "https://raw.githubusercontent.com/MAKE-MONEY-MILLION-DOLLAR-PER-DAY/7net-Team/refs/heads/main/7net%2BAll_Team.js"
    },
    "xhypher": {
        "KEY_SEED": bytes([
            0xBE, 0x97, 0xB5, 0x61, 0x2D, 0x7C, 0x13, 0x78, 0x7B,
            0x64, 0xE2, 0xCB, 0x37, 0x3D, 0x3D, 0x22, 0x88, 0x11,
            0x96, 0x23, 0xAA, 0xA0, 0xCA, 0x8D, 0xFE, 0xB0, 0xC7,
            0xBC, 0xD3, 0xA8, 0xDF, 0x85
        ]),
        "IV": bytes([
            0x0C, 0x0C, 0xA9, 0x25, 0xCA, 0xFD, 0x24, 0x38, 0xF9,
            0x85, 0xFC, 0x35, 0xE6, 0x09, 0x80, 0x7D
        ]),
        "FIXED_SALT": bytes([
            0x2F, 0x09, 0xB4, 0xA5, 0x55, 0x85, 0x3A, 0x46, 0xB5,
            0x05, 0x7F, 0x6B, 0x9E, 0x50, 0xE0, 0x32, 0x2E, 0x76,
            0xF5, 0x66, 0x48, 0x76, 0x23, 0xC7, 0x01, 0x19, 0xBC,
            0xEB, 0x12, 0x17, 0x8E, 0x83
        ]),
        "URL": "https://raw.githubusercontent.com/XyrussProject/infinite88/refs/heads/main/xhyphertunnelpro888.hs"
    },
    "safetunnel": {
        "KEY_SEED": bytes([
            0xD7, 0x64, 0x40, 0x58, 0x2C, 0x3D, 0x26, 0xD9,
            0xF2, 0x7E, 0xA3, 0x95, 0x6A, 0x63, 0xE0, 0x7A,
            0x10, 0x39, 0x0E, 0x9C, 0xDC, 0x75, 0x5B, 0x7A,
            0xB8, 0xD5, 0x9B, 0xE8, 0xD7, 0x03, 0x5E, 0x89
        ]),
        "IV": bytes([
            0x2F, 0x12, 0xC9, 0xB8, 0x44, 0x79, 0xA3, 0x6D,
            0x93, 0x73, 0x83, 0xC9, 0x3B, 0xD1, 0x06, 0x5B
        ]),
        "FIXED_SALT": bytes([
            0xA2, 0x9E, 0xDD, 0x4B, 0xED, 0xF3, 0x77, 0x9B,
            0x73, 0x0B, 0x4D, 0x99, 0x83, 0x87, 0xC4, 0x99,
            0x87, 0xA5, 0x3C, 0x85, 0x97, 0x59, 0x37, 0x4E,
            0xAB, 0x74, 0x3C, 0xC7, 0x38, 0xAD, 0xCA, 0x56
        ]),
        "URL": "https://24tunnel.xyz/api/files/app?json=ff50be4e4a84ee43a260"
    },
    "mhrtunnel": {
        "KEY_SEED": bytes([
            0x98, 0xEE, 0xFC, 0xE9, 0x5F, 0x00, 0x92, 0x3D,
            0x10, 0x45, 0xC8, 0x71, 0x14, 0x2E, 0x33, 0x2B,
            0x63, 0xEB, 0x86, 0xA3, 0xE7, 0x32, 0xE5, 0x8B,
            0x0C, 0xB8, 0xE6, 0x59, 0x58, 0xDE, 0xF7, 0xB7
        ]),
        "IV": bytes([
            0x9A, 0xA6, 0x53, 0x7C, 0x94, 0x05, 0x7F, 0x7F,
            0x33, 0x8A, 0x62, 0x7C, 0x00, 0xFF, 0x83, 0x38
        ]),
        "FIXED_SALT": bytes([
            0x37, 0xD7, 0x9B, 0x96, 0x80, 0xF6, 0x4E, 0xE1,
            0x87, 0x21, 0xFB, 0xEF, 0x00, 0xE4, 0x8B, 0x37,
            0xA4, 0x1B, 0x54, 0x4D, 0x4C, 0x00, 0xBB, 0xA7,
            0x8F, 0xF3, 0xA5, 0xF7, 0x11, 0xDD, 0xEB, 0x52
        ]),
        "URL": "https://mhrbro.xyz/api/app?json=8f73b1b244aef98cd9c6"
    },
    "actunnelvpn": {
        "KEY_SEED": bytes([
            0x3D, 0xF2, 0x20, 0x60, 0x48, 0xB6, 0xA9, 0x68,
            0x99, 0xC6, 0x4C, 0xBD, 0x24, 0x4C, 0xA4, 0xB9,
            0x4E, 0x4F, 0x63, 0xD8, 0x16, 0xC9, 0xE6, 0x1A,
            0xB5, 0xAF, 0x52, 0x61, 0x81, 0x89, 0x1E, 0x82
        ]),
        "IV": bytes([
            0x81, 0xCC, 0x11, 0xEC, 0xAC, 0x72, 0x9B, 0x67,
            0xE5, 0x4C, 0x9F, 0x08, 0x75, 0x20, 0xE1, 0xD4
        ]),
        "FIXED_SALT": bytes([
            0x89, 0x6A, 0x67, 0x3B, 0x34, 0xF9, 0xC9, 0x83,
            0x2A, 0x3E, 0x0F, 0x63, 0x06, 0x0F, 0xB9, 0x90,
            0xAB, 0xAF, 0xE2, 0xBF, 0xFC, 0x58, 0xF5, 0x94,
            0x47, 0x47, 0xFC, 0xFD, 0xF6, 0x3C, 0x69, 0x7B
        ]),
        "URL": "https://rttunnelv2ray.xyz/api/files/app?json=7ef7a9a142eb1f77a56f"
    },
    "letsvpngo": {
        "KEY_SEED": bytes([
            0xD6, 0x86, 0xD5, 0x0A, 0x0B, 0x1F, 0xAE, 0x2D,
            0x42, 0x37, 0xF4, 0xC9, 0x98, 0x0C, 0x26, 0x7A,
            0xDC, 0x52, 0x17, 0x21, 0x17, 0xEA, 0x0B, 0x19,
            0xC2, 0x67, 0x1F, 0xBB, 0x87, 0xB9, 0xF8, 0x10
        ]),
        "IV": bytes([
            0xBA, 0x69, 0x31, 0xB3, 0x1B, 0x75, 0x84, 0x58,
            0x0B, 0x71, 0x47, 0x6A, 0xC9, 0xCA, 0x38, 0x9F
        ]),
        "FIXED_SALT": bytes([
            0xCB, 0xFE, 0x76, 0x27, 0xE8, 0xD0, 0x36, 0x9A,
            0xFC, 0xD3, 0xD2, 0xD6, 0x4D, 0x9E, 0x09, 0x9B,
            0x13, 0xF7, 0x0F, 0xD8, 0x89, 0x03, 0xB2, 0x66,
            0x67, 0x57, 0x08, 0xD1, 0x88, 0x1E, 0x7A, 0xD6
        ]),
        "URL": "https://raw.githubusercontent.com/TkMasterc/LetsVPN/refs/heads/main/README.md"
    },
    "aloplusvpn": {
        "KEY_SEED": bytes([
            0x14, 0xD5, 0xDD, 0x67, 0x5A, 0x20, 0x71, 0x10,
            0x22, 0x34, 0x6E, 0x9C, 0x2A, 0x5C, 0xE9, 0xD9,
            0x19, 0xDE, 0x4E, 0xA3, 0xD1, 0xD6, 0xAD, 0xB8,
            0xCD, 0x4E, 0x12, 0xBA, 0xB5, 0x5B, 0xE2, 0x3B
        ]),
        "IV": bytes([
            0xCB, 0x4C, 0x22, 0xFD, 0xF6, 0x29, 0x73, 0x28,
            0xC6, 0xEB, 0x47, 0xDF, 0x41, 1, 0x88, 0x43
        ]),
        "FIXED_SALT": bytes([
            0x73, 0xE1, 0xF8, 0x2C, 0xBE, 0xF0, 0x52, 0x5D,
            0xF1, 0x87, 0x46, 0xED, 0xC, 0x2B, 0, 0x6C,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0
        ])
    },
    "cranetunnel": {
        "KEY_SEED": bytes.fromhex("4c 7d 71 66 2f 6a 3f 36 32 43 5e 40 51 6d 5a 59 3b 56 5f 38 5d 21"),
        "IV": bytes.fromhex("82 aa 46 e4 88 64 4f 9f 3a f6 b6 1b 69 d2 14 cd"),
        "FIXED_SALT": bytes.fromhex("1A 2B 3C 4D 5E 6F 7A 8B 9C AD BE CF D0 E1 F2 03"),
        "URL": "https://exoticfastvip.xyz/api/app?json=ce047188e581f0511d18"
    },
    "tcxtunnel": {
        "URL": "https://raw.githubusercontent.com/maunadonis/aug16/refs/heads/main/aug16"
    },
    "trptunnel": {
        "URL": "https://raw.githubusercontent.com/Jcacanog12/trinet-pro-reborn-auto/refs/heads/main/Trinetv5"
    },
    "vipsnipherpro": {
        "KEY_SEED": bytes.fromhex(
            "1fea453c1c20a9366214bf96b64a26f1"
            "b76e32660d02ab66a1ddc878936186b1"
        ),
        "IV": bytes.fromhex("82aa46e488644f9f3af6b61b69d214cd"),
        "FIXED_SALT": bytes.fromhex(
            "c9c5fd1cace2fe51e213935313b2f03b"
            "a055190f23b4aced90c36cf3cb43d291"
        ),
        "URL": "https://raw.githubusercontent.com/Civ3snipher/NEW-VIP-SNIPHER-PRO/refs/heads/main/update.json?ref=main"
    },
    "deshtunnelvpn": {
        "KEY_SEED": bytes.fromhex(
            "c68cef64726926d6d015c014193fb2aa"
            "340de62fc02f7fd80ad5ebce25f514e0"
        ),
        "IV": bytes.fromhex(
            "da71a9be643a32c6394a3e7224da0ac6"
        ),
        "FIXED_SALT": bytes.fromhex(
            "6c9eb9afbdfe8b1bdc4959f3167aba25"
            "7c7b2b5b0acd760ec58bf2cff32f6ab4"
        ),
        "URL": "https://deshvpn.com/uploads/json/50d7a092eae37dc25766.json"
    },
    "hamotunnelplus": {
        "KEY_SEED": bytes.fromhex(
            "deb72221be4652c347f930e85adc2997"
            "0ccd499cf42e361b3d6b14918912bf3b"
        ),
        "IV": bytes.fromhex(
            "2d2f3112a271edbba9a41ad58a3a99bf"
        ),
        "FIXED_SALT": bytes.fromhex(
            "70ed508428ff7b5bcde0bcdd3b947493"
            "2ab1cabc5ff6870e6e584b4fa7925f55"
        ),
        "URL": "https://raw.githubusercontent.com/MAKE-MONEY-MILLION-DOLLAR-PER-DAY/ENZ-TUNNEL-Lite/refs/heads/main/ENZ_Tunnel.js"
    },
    "gcpvpn": {
        "KEY_SEED": bytes.fromhex(
            "8968cb6e895105be625839ad9b9ba6ac"
            "e8dcd4413d7c5ecfaa1069413ffeb044"
        ),
        "IV": bytes.fromhex(
            "49e59fdf67eb479ce8b96c24d2495bd1"
        ),
        "FIXED_SALT": bytes.fromhex(
            "c27fd7bee17196d650530886cf4c24f5"
            "2cac5abb8bff6ad3a48ebb10f4b1f632"
        ),
        "URL": "https://raw.githubusercontent.com/kiranoble/config/refs/heads/main/gcpvpn2026"
    }
}

RENZ_DELTA_V2 = 2052510689
RENZ_OFFSET_V2 = 569837754

def renz_sub_3A8E48(c: int) -> int:
    if 65 <= c <= 90:      # 'A'-'Z'
        return c - 65
    if 97 <= c <= 122:     # 'a'-'z'
        return c - 71      # 97 - 71 = 26
    if 48 <= c <= 57:      # '0'-'9'
        return c + 4       # 48 + 4 = 52
    if c <= 0x2E:          # <= '.'
        if c == 43 or c == 45:  # '+' ou '-'
            return 62
    else:
        if c == 95 or c == 47:  # '_' ou '/'
            return 63
    raise ValueError("Input is not valid base64-encoded data.")

def renz_base64_decode_custom(data: bytes, strip_newlines: bool) -> bytes:
    if not data:
        return b""
    if strip_newlines:
        data = data.replace(b'\n', b'')

    out = bytearray()
    n = len(data)
    i = 0

    while i < n:
        c0 = data[i]
        c1 = data[i + 1] if i + 1 < n else ord('=')

        v0 = renz_sub_3A8E48(c0)
        v1 = renz_sub_3A8E48(c1)
        v21 = v1

        out.append(((v0 << 2) | ((v1 >> 4) & 0x03)) & 0xFF)

        if i + 2 < n:
            c2 = data[i + 2]
            if c2 not in (61, 46):  # '=' ou '.'
                v2 = renz_sub_3A8E48(c2)
                out.append((((v21 << 4) & 0xF0) | ((v2 >> 2) & 0x0F)) & 0xFF)

                if i + 3 < n:
                    c3 = data[i + 3]
                    if c3 not in (61, 46):
                        v3 = renz_sub_3A8E48(c3)
                        out.append(((v2 << 6) & 0xC0) | (v3 & 0x3F))

        i += 4

    return bytes(out)

def renz_aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        pad = plaintext[-1]
        if pad < 1 or pad > 16:
            return b"", False
        if plaintext[-pad:] != bytes([pad]) * pad:
            return b"", False
        return plaintext[:-pad], True
    except Exception:
        return b"", False

def renz_prepare_key_xxtea(key: bytes) -> list[int]:
    k = bytearray(key[:16].ljust(16, b'\x00'))
    for i in range(15):
        if k[i] == 0:
            for j in range(i + 1, 16):
                k[j] = 0
            break
    return list(struct.unpack('<4I', k))

def renz_mx(sum_val: int, y: int, z: int, p: int, e: int, k: list[int]) -> int:
    return (
        (
            ((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))
        ) ^ (
            (sum_val ^ y) + (k[(p & 3) ^ e] ^ z)
        )
    ) & 0xFFFFFFFF

def renz_xxtea_decrypt_custom(data: bytes, key: bytes, vpn: str = ""):
    a2 = len(data)
    delta = RENZ_DELTA_V2
    offset = RENZ_OFFSET_V2
    if vpn == "tcxtunnel":
        delta = 0x9E3779B9
        offset = 0x4AB325AA
    if a2 == 0:
        return b"", 0

    k = renz_prepare_key_xxtea(key)
    v8 = (a2 >> 2) + 1 if (a2 & 3) != 0 else (a2 >> 2)
    buf = bytearray(v8 * 4)
    buf[:a2] = data
    v = list(struct.unpack('<%dI' % v8, buf))

    if v8 != 1:
        rounds = 0x34 // v8
        sum_val = (delta * rounds - offset) & 0xFFFFFFFF
        if delta * rounds != offset:
            n = v8
            y = v[0]
            while sum_val != 0:
                e = (sum_val >> 2) & 3
                for p in range(n - 1, 0, -1):
                    z = v[p - 1]
                    v[p] = (v[p] - renz_mx(sum_val, y, z, p, e, k)) & 0xFFFFFFFF
                    y = v[p]
                z = v[n - 1]
                v[0] = (v[0] - renz_mx(sum_val, y, z, 0, e, k)) & 0xFFFFFFFF
                y = v[0]
                sum_val = (sum_val - delta) & 0xFFFFFFFF

    buf = struct.pack('<%dI' % v8, *v)
    total_bytes = 4 * v8
    last_word = v[-1]

    if total_bytes - 7 <= last_word <= total_bytes - 4:
        out_len = last_word
        return buf[:out_len], out_len
    else:
        return b"", 0

def renz_trp_decrypt(config):
    xxtea_input = base64.b64decode(config)
    xxtea_key = bytes.fromhex("91f9eea7eb614fbbff2521e76306cea4")
    aes_key = bytes.fromhex("91f9eea7eb614fbbff2521e76306cea4")
    iv = b"\x00" * 16

    xxtea_out, _ = renz_xxtea_decrypt_custom(xxtea_input, xxtea_key, "tcxtunnel")
    aes_out, _ = renz_aes_decrypt(xxtea_out, aes_key, iv)
    return aes_out.decode(errors="ignore")

def renz_tcx_decrypt(config):
    xxtea_input = base64.b64decode(config)
    xxtea_key = bytes.fromhex("61 03 10 2f 3d fa 7c ac 1a a5 b8 ff 4b a1 20 22")
    aes_key = bytes.fromhex("61 03 10 2f 3d fa 7c ac 1a a5 b8 ff 4b a1 20 22 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")[:16]
    iv = b"\x00" * 16

    xxtea_out, _ = renz_xxtea_decrypt_custom(xxtea_input, xxtea_key, "tcxtunnel")
    aes_out, _ = renz_aes_decrypt(xxtea_out, aes_key, iv)
    return aes_out.decode(errors="ignore")

def renz_decrypt_main(b64_input: bytes, vpn, notj=0) -> bytes:
    if vpn == "tcxtunnel":
        if isinstance(b64_input, bytes):
            return renz_tcx_decrypt(b64_input.decode())
        return renz_tcx_decrypt(b64_input)
    elif vpn == "trptunnel":
        if isinstance(b64_input, bytes):
            return renz_trp_decrypt(b64_input.decode())
        return renz_trp_decrypt(b64_input)

    decoded = base64.b64decode(b64_input)
    KEY_SEED = RENZ_KEYS[vpn]["KEY_SEED"]
    IV = RENZ_KEYS[vpn]["IV"]

    key16 = hashlib.sha256(KEY_SEED).digest()[:16]
    aes_plain, ok = renz_aes_decrypt(decoded, key16, IV)
    if not ok:
        return ""

    xx_plain, out_len = renz_xxtea_decrypt_custom(aes_plain, key16)
    if out_len == 0:
        return ""

    if not vpn in ["xhypher", "safetunnel", "mhrtunnel", "letsvpngo"]:
        final = bytes((b - 2) & 0xFF for b in xx_plain[:out_len])
    else:
        final = xx_plain
    return final.decode()

def renz_hkdf_sha256(key_material: bytes, salt: bytes, length: int) -> bytes:
    prk = hmac.new(salt, key_material, hashlib.sha256).digest()
    okm, prev, counter = b"", b"", 1
    while len(okm) < length:
        prev = hmac.new(prk, prev + bytes([counter]), hashlib.sha256).digest()
        okm += prev
        counter += 1
    return okm[:length]

def renz_generate_hkdf_key(key_material: bytes, salt: bytes) -> bytes:
    return renz_hkdf_sha256(key_material, salt[:16], 16)

def renz_generate_hkdf32_key(key_material: bytes, salt: bytes) -> bytes:
    return renz_hkdf_sha256(key_material, salt, 32)

def renz_patch_hkdf_a(hkdf32: bytes) -> bytes:
    acc1 = bytearray(16)
    acc2 = bytearray(16)
    for i in range(0, len(hkdf32), 16):
        chunk = hkdf32[i:i+16]
        if len(chunk) < 16:
            break
        for j in range(16):
            acc1[j] ^= chunk[j]
            acc2[j] ^= chunk[::-1][j]
    final = bytes(a ^ b for a, b in zip(acc1, acc2))
    return hkdf32 + final

def renz_decrypt_speciale(input_b64: str, vpn: str) -> bytes | None:
    if vpn == "xhypher" and input_b64:
        if __package__:
            from .apps.Xhypher_Tunnel_Pro.codec import decode_special
        else:
            from apps.Xhypher_Tunnel_Pro.codec import decode_special
        return decode_special(input_b64)
    limite = False
    if vpn == "tcxtunnel":
        return renz_tcx_decrypt(input_b64)
    if vpn == "trptunnel":
        return renz_trp_decrypt(input_b64)
    if vpn.lower().startswith("xhkypher"):
        limite = True
    if not input_b64:
        return None

    raw = base64.b64decode(input_b64)
    byte_2050B8 = RENZ_KEYS[vpn]["KEY_SEED"]
    salt = RENZ_KEYS[vpn].get("FIXED_SALT", b"0" * 32)
    iv = RENZ_KEYS[vpn]["IV"]
    hkdf16 = renz_generate_hkdf_key(byte_2050B8, salt)
    hkdf32 = renz_generate_hkdf32_key(byte_2050B8, salt)

    if vpn in ["aloplusvpn",]:
        hkdf16 = renz_generate_hkdf_key(byte_2050B8, salt)
        hkdf32 = renz_generate_hkdf32_key(byte_2050B8, salt)
        hkdf32 = renz_patch_hkdf_a(hkdf32)

    key_words = [
        int.from_bytes(hkdf32[i:i+8], "little")
        for i in range(0, len(hkdf32), 8)
    ]
    if vpn == "cranetunnel":
        xxt, _ = renz_xxtea_decrypt_custom(raw, hkdf16)
        aes, _ = renz_aes_decrypt(xxt, hkdf16, iv)
        return aes.decode(errors="ignore")

    decrypted_tf = bytearray()
    block_size = 32

    for i in range(0, len(raw), block_size):
        block = raw[i:i+block_size]
        if len(block) < block_size:
            break

        block_words = [
            int.from_bytes(block[j:j+8], "little")
            for j in range(0, block_size, 8)
        ]
        block_index = i // block_size
        if vpn in ["vipsnipherpro"]:
            block_index = 0
        t0 = block_index
        t1 = block_index * 64
        if vpn in ["7net", "actunnelvpn", "osptunnel", "actun", "vipsnipherpro", "deshtunnelvpn", "hamotunnelplus"]:
            t1 = 0
        elif vpn in ["xhypher", "safetunnel", "mhrtunnel", "letsvpngo"]:
            t1 = block_index * 192
        elif vpn in ["aloplusvpn",]:
            t1 = 0
            for idx, w in enumerate(block_words):
                t1 ^= (w + idx)
            t1 ^= block_index * 160

        a1 = threefish_set_key(256, key_words, [t0, t1])
        block_words = [
            int.from_bytes(block[j:j+8], "little")
            for j in range(0, block_size, 8)
        ]
        out_words = [0, 0, 0, 0]
        threefish_decrypt256_block(a1, block_words, out_words)

        for w in out_words:
            decrypted_tf += w.to_bytes(8, "little")

    while decrypted_tf and decrypted_tf[-1] == 0:
        decrypted_tf.pop()

    cipher = AES.new(hkdf16, AES.MODE_CBC, iv)
    decrypted_aes = cipher.decrypt(bytes(decrypted_tf))
    try:
        decrypted_aes = unpad(decrypted_aes, 16)
    except ValueError:
        pass
    if limite:
        decrypted_aes = decrypted_aes[:32]
    try:
        decrypted_aes = decrypted_aes.decode()
    except Exception:
        decrypted_aes = decrypted_aes.decode(errors="ignore")
    return decrypted_aes

def renz_strip_control_padding(b):
    while b and b[-1] <= 0x1F:
        b = b[:-b[-1]]
    return b

def renz_decrypt_sensitive(data_b64: str, vpn: str):
    # Xhypher build 43 wraps the existing sensitive-field cipher in an
    # invisible Unicode carrier. Keep historical Base64 paths unchanged.
    if vpn == "xhypher" and any(c in data_b64 for c in "\u200b\u200c\u200d"):
        if __package__:
            from .apps.Xhypher_Tunnel_Pro.codec import decode_sensitive
        else:
            from apps.Xhypher_Tunnel_Pro.codec import decode_sensitive
        return decode_sensitive(data_b64)
    if vpn == "tcxtunnel":
        try:
            return renz_tcx_decrypt(data_b64)
        except Exception:
            return data_b64
    if vpn == "trptunnel":
        try:
            return renz_trp_decrypt(data_b64)
        except Exception:
            return data_b64

    byte_2050B8 = RENZ_KEYS[vpn]["KEY_SEED"]
    key_len = 32
    if vpn == "cranetunnel":
        key_len = 16
    salt = RENZ_KEYS[vpn].get("FIXED_SALT", b"0" * key_len)
    iv = RENZ_KEYS[vpn]["IV"]
    data = base64.b64decode(data_b64)

    key = hashlib.pbkdf2_hmac('sha256', byte_2050B8, salt, 100000, key_len)
    data, dlen = renz_xxtea_decrypt_custom(data, key)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(data)

    if not decrypted:
        return ""
    pad_len = decrypted[-1]
    if pad_len > 0 and pad_len <= len(decrypted):
        decrypted = decrypted[16:-pad_len]
    else:
        decrypted = decrypted[16:]
    try:
        if vpn != "cranetunnel":
            decrypted = renz_strip_control_padding(decrypted).decode(errors="ignore")
        else:
            decrypted = decrypted.decode(errors="ignore")
    except Exception:
        decrypted = ""
    return decrypted

def renz_recursive_decrypt_main(data, vpn):
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, str) and len(v) > 20:
                try:
                    if vpn == "tcxtunnel":
                        dec = renz_tcx_decrypt(v)
                        if dec:
                            data[k] = dec
                    elif vpn == "trptunnel":
                        dec = renz_trp_decrypt(v)
                        if dec:
                            data[k] = dec
                    elif "host" in k.lower() or "path" in k.lower():
                        dec = renz_decrypt_speciale(v, vpn)
                        if dec:
                            data[k] = dec
                    elif "username" in k.lower() or "password" in k.lower():
                        dec = renz_decrypt_sensitive(v, vpn)
                        if dec:
                            data[k] = dec
                    else:
                        dec = renz_decrypt_main(v.encode(), vpn)
                        if dec:
                            data[k] = dec
                        else:
                            dec = renz_decrypt_speciale(v, vpn)
                            if dec:
                                data[k] = dec
                except Exception:
                    pass
            elif isinstance(v, (dict, list)):
                renz_recursive_decrypt_main(v, vpn)
    elif isinstance(data, list):
        for item in data:
            renz_recursive_decrypt_main(item, vpn)
    return data


# The source's alternative Type 1 decoder required optional PySkein.
# Reuse its bundled, pure-Python Threefish-256 core so all four legacy
# RENZ types remain available on a normal SP-DECODE Python installation.
def renz_threefish256_decrypt(data: bytes, key_mat: bytes) -> bytes:
    if len(key_mat) != 32 or len(data) % 32:
        raise RENZError("invalid Threefish-256 key or block size")
    key_words = list(struct.unpack("<4Q", key_mat))
    result = bytearray()
    for offset in range(0, len(data), 32):
        words = list(struct.unpack("<4Q", data[offset:offset + 32]))
        keys = threefish_set_key(256, key_words, [offset // 32, 0])
        plain = [0, 0, 0, 0]
        threefish_decrypt256_block(keys, words, plain)
        result.extend(struct.pack("<4Q", *plain))
    return bytes(result)

RENZ_SKEIN_OK = True  # All type1 operations use the pure-Python implementation.


def renz_get_hkdf_key_16() -> bytes:
    return renz_hkdf_sha256(RENZ_BASE_MATERIAL, RENZ_FIXED_SALT[:16], 16)

def renz_get_hkdf_key() -> bytes:
    return renz_hkdf_sha256(RENZ_BASE_MATERIAL, RENZ_FIXED_SALT, 32)

def renz_get_pbkdf2_key() -> bytes:
    return renz_pbkdf2_sha256(RENZ_BASE_MATERIAL, RENZ_FIXED_SALT, 100000, 32)

def renz_decrypt_type0(payload: bytes) -> bytes:
    s1 = renz_aes128_cbc_fixed(payload, RENZ_SHA256_KEY_16)
    s2 = renz_xxtea_decrypt(s1, RENZ_SHA256_KEY_16)
    return bytes((b-2)&0xFF for b in s2)

def renz_decrypt_type1(payload: bytes) -> bytes:
    key16 = renz_get_hkdf_key_16()
    key32 = renz_get_hkdf_key()
    try:
        text = payload.decode('utf-8')
        b64 = renz_base64_decode_android(text)
    except:
        raise RENZError("type1 decode fail")
    s2 = renz_threefish256_decrypt(b64, key32).rstrip(b'\x00')
    return renz_aes128_cbc_fixed(s2, key16)

def renz_decrypt_type2(payload: bytes) -> bytes:
    key32 = renz_get_pbkdf2_key()
    try:
        text = payload.decode('utf-8')
        b64 = renz_base64_decode_android(text)
    except:
        raise RENZError("type2 decode fail")
    s2 = renz_xxtea_decrypt(b64, key32[:16])
    return renz_aes256_cbc_prefixed_iv(s2, key32)

def renz_decrypt_type3(payload: bytes) -> bytes:
    return renz_aes256_cbc_prefixed_iv(payload, renz_get_hkdf_key())

# ========== دوال فك التشفير العميقة (المتداخلة) ==========
def renz_try_decrypt_field(value: str, decryptors) -> str:
    """محاولة فك تشفير حقل نصي باستخدام كل الأنواع المتاحة"""
    for kind, func in decryptors.items():
        # المحاولة على النص الخام
        try:
            dec = func(value.encode('utf-8'))
            txt = dec.decode('utf-8')
            if txt and len(txt) > 5:
                # إذا كان النص يبدو وكأنه نص عادي (لا يحتوي على base64 طويل)
                if not re.match(r'^[A-Za-z0-9+/=]+$', txt.strip()):
                    return txt
        except:
            pass
        # المحاولة على النص بعد فك base64
        try:
            b64 = renz_base64_decode_android(value)
            dec = func(b64)
            txt = dec.decode('utf-8')
            if txt and len(txt) > 5 and not re.match(r'^[A-Za-z0-9+/=]+$', txt.strip()):
                return txt
        except:
            pass
    return value

def renz_decrypt_nested(obj, decryptors, path=""):
    """تعديل الكائن في المكان: فك تشفير كل الحقول النصية"""
    if isinstance(obj, dict):
        for k, v in list(obj.items()):
            if isinstance(v, str) and len(v) > 10:
                decrypted = renz_try_decrypt_field(v, decryptors)
                if decrypted != v:
                    obj[k] = decrypted
            elif isinstance(v, (dict, list)):
                renz_decrypt_nested(v, decryptors, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            renz_decrypt_nested(item, decryptors, f"{path}[{i}]")


# Only file suffixes routed through RENZ in 66.py's document handler.
# Exclusions: .vlx is owned by Ultra/Sandok and RENZ_KEYS has no 'vlx' profile;
# .izph is a separate later phase despite a legacy IZPH key dictionary entry.
RENZ_FILE_EXTENSIONS: dict[str, str] = {
    ".7net": "7net",
    ".actunnelvpn": "actunnelvpn",
    ".actun": "actunnelvpn",  # Source typo: 'actun' missing from RENZ_KEYS.
    ".xhypher": "xhypher",
    ".tcx": "tcxtunnel",
    ".bshield": "bshield",
    ".osp": "7net",
    ".safetunnel": "safetunnel",
    ".mhrtunnel": "mhrtunnel",
    ".letsvpngo": "letsvpngo",
    ".aloplusvpn": "aloplusvpn",
    ".cranetunnel": "cranetunnel",
    ".vipsnipherpro": "vipsnipherpro",
    ".deshtunnelvpn": "deshtunnelvpn",
    ".hamotunnelplus": "hamotunnelplus",
    ".gcpvpn": "gcpvpn",
}

RENZ_TEXT_PROTOCOLS: dict[str, str] = {
    "7net://": "7net", "7netvpn://": "7net",
    "tcx://": "tcxtunnel", "tcxtunnelplus://": "tcxtunnel",
    "ihome://": "7net", "ihomevpn://": "7net",
    "xhypher://": "xhypher", "xhyphertunnelpro://": "xhypher",
    "osp://": "7net", "osptunnel://": "7net",
    "actunnelvpn://": "actunnelvpn", "actunnel://": "actunnelvpn",
    "bshieldnet://": "bshield", "bshield://": "bshield",
    "safetunnel://": "safetunnel", "mhrtunnel://": "mhrtunnel",
    "letsvpngo://": "letsvpngo", "aloplusvpn://": "aloplusvpn",
    "cranetunnel://": "cranetunnel", "vipsnipherpro://": "vipsnipherpro",
    "deshtunnelvpn://": "deshtunnelvpn",
    "hamotunnelplus://": "hamotunnelplus", "gcpvpn://": "gcpvpn",
}

RENZ_FILE_NAMES = {
    ext: ("RENZ / 7NET" if name == "7net" else
          "RENZ / " + name.upper()) for ext, name in RENZ_FILE_EXTENSIONS.items()
}


def _decode_typed_7net(payload: bytes) -> object | None:
    """The source has a second RENZ route: types 0, 1, 2 and 3."""
    functions = (
        renz_decrypt_type0, renz_decrypt_type1,
        renz_decrypt_type2, renz_decrypt_type3,
    )
    for func in functions:
        for candidate in (payload,):
            try:
                value = func(candidate)
                config = json.loads(value.decode("utf-8"))
                if isinstance(config, (dict, list)):
                    funcs = {0: renz_decrypt_type0, 1: renz_decrypt_type1,
                             2: renz_decrypt_type2, 3: renz_decrypt_type3}
                    renz_decrypt_nested(config, funcs)
                    return config
            except (ValueError, TypeError, KeyError, UnicodeDecodeError, RENZError):
                pass
        try:
            candidate = renz_base64_decode_android(payload.decode("utf-8"))
            value = func(candidate)
            config = json.loads(value.decode("utf-8"))
            if isinstance(config, (dict, list)):
                funcs = {0: renz_decrypt_type0, 1: renz_decrypt_type1,
                         2: renz_decrypt_type2, 3: renz_decrypt_type3}
                renz_decrypt_nested(config, funcs)
                return config
        except (ValueError, TypeError, KeyError, UnicodeDecodeError, RENZError):
            pass
    return None


def _decode_config(payload: str, variant: str) -> object | None:
    if variant not in RENZ_KEYS:
        return None
    try:
        plaintext = renz_decrypt_main(payload.encode("utf-8"), variant)
        if not isinstance(plaintext, str) or not plaintext.strip():
            raise RENZError("no plaintext")
        parsed = json.loads(plaintext)
        if not isinstance(parsed, (dict, list)):
            raise RENZError("configuration is not an object or array")
        return renz_recursive_decrypt_main(parsed, variant)
    except (ValueError, KeyError, IndexError, TypeError, UnicodeError, RENZError):
        if variant == "7net":
            return _decode_typed_7net(payload.encode("utf-8"))
        return None


def decode_file(data: bytes, extension: str) -> str | None:
    ext = "." + extension.lower().lstrip(".")
    variant = RENZ_FILE_EXTENSIONS.get(ext)
    if variant is None or not data or len(data) > MAX_INPUT_BYTES:
        return None
    try:
        text = data.decode("utf-8").strip()
        # Accept only the explicitly registered textual aliases.
        if "://" in text:
            prefix, text = text.split("://", 1)
            prefix = prefix.lower() + "://"
            if RENZ_TEXT_PROTOCOLS.get(prefix) != variant:
                return None
        config = _decode_config(text, variant)
        if config is None:
            return None
        return json.dumps({
            "application": RENZ_FILE_NAMES[ext],
            "extension": ext,
            "config": config,
        }, ensure_ascii=False, indent=2)
    except (UnicodeDecodeError, ValueError, TypeError):
        return None


def decode_text(text: str) -> str | None:
    if not text or len(text.encode("utf-8")) > MAX_INPUT_BYTES:
        return None
    raw = text.strip()
    prefix, delim, payload = raw.partition("://")
    if not delim:
        return None
    variant = RENZ_TEXT_PROTOCOLS.get(prefix.lower() + delim)
    if variant is None or not payload:
        return None
    config = _decode_config(payload.strip(), variant)
    if config is None:
        return None
    return json.dumps({
        "application": RENZ_FILE_NAMES.get("." + prefix.lower(),
                                             "RENZ / " + variant.upper()),
        "protocol": prefix.lower() + delim,
        "config": config,
    }, ensure_ascii=False, indent=2)


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python renz.py <configuration-file>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    if path.suffix.lower() not in RENZ_FILE_EXTENSIONS:
        print("Unsupported RENZ extension", file=sys.stderr)
        return 2
    try:
        result = decode_file(path.read_bytes(), path.suffix)
    except OSError as exc:
        print(f"Cannot read file: {exc}", file=sys.stderr)
        return 1
    if result is None:
        print("Unable to decrypt RENZ configuration", file=sys.stderr)
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
