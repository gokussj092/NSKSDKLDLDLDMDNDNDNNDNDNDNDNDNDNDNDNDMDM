#!/usr/bin/env python3
"""Pure-Python crypto helpers for SP-DECODE method dossiers (synthetic tests only).

Written for this dossier from the public FIPS-197 (AES) / XXTEA / Threefish
specifications. Stdlib only, no network, no secrets: every key used by the
dossier tests is a synthetic test key generated inside the test itself.

Contents:
  - AES-128/192/256 block encrypt/decrypt, CBC with PKCS#7, GCM (GHASH).
  - XXTEA (delta configurable) encrypt/decrypt with the RENZ length-word
    convention used by the catalog scripts (last word = plaintext length).
  - Threefish-256 encrypt/decrypt (72 rounds, tweak schedule).
"""
import struct

# --- AES (FIPS-197 tables, public standard) ---------------------------------
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
            t = [_SBOX[t[1]] ^ _RCON[i // nk - 1], _SBOX[t[2]], _SBOX[t[3]], _SBOX[t[0]]]
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w, nr


def _add_rk(s, w, rnd):
    for c in range(4):
        for r in range(4):
            s[r + 4 * c] ^= w[rnd * 4 + c][r]


def _sub(s, inv=False):
    box = _INV_SBOX if inv else _SBOX
    return [box[b] for b in s]


def _shift(s, inv=False):
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            if inv:
                out[r + 4 * c] = s[r + 4 * ((c - r) % 4)]
            else:
                out[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
    return out


def _mix(s, inv=False):
    out = [0] * 16
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        if inv:
            out[4 * c:4 * c + 4] = [
                _mul(col[0], 14) ^ _mul(col[1], 11) ^ _mul(col[2], 13) ^ _mul(col[3], 9),
                _mul(col[0], 9) ^ _mul(col[1], 14) ^ _mul(col[2], 11) ^ _mul(col[3], 13),
                _mul(col[0], 13) ^ _mul(col[1], 9) ^ _mul(col[2], 14) ^ _mul(col[3], 11),
                _mul(col[0], 11) ^ _mul(col[1], 13) ^ _mul(col[2], 9) ^ _mul(col[3], 14),
            ]
        else:
            out[4 * c:4 * c + 4] = [
                _mul(col[0], 2) ^ _mul(col[1], 3) ^ col[2] ^ col[3],
                col[0] ^ _mul(col[1], 2) ^ _mul(col[2], 3) ^ col[3],
                col[0] ^ col[1] ^ _mul(col[2], 2) ^ _mul(col[3], 3),
                _mul(col[0], 3) ^ col[1] ^ col[2] ^ _mul(col[3], 2),
            ]
    return out


def aes_encrypt_block(key, block):
    w, nr = _key_expansion(key)
    s = list(block)
    _add_rk(s, w, 0)
    for rnd in range(1, nr):
        s = _sub(s)
        s = _shift(s)
        s = _mix(s)
        _add_rk(s, w, rnd)
    s = _sub(s)
    s = _shift(s)
    _add_rk(s, w, nr)
    return bytes(s)


def aes_decrypt_block(key, block):
    w, nr = _key_expansion(key)
    s = list(block)
    _add_rk(s, w, nr)
    for rnd in range(nr - 1, 0, -1):
        s = _shift(s, inv=True)
        s = _sub(s, inv=True)
        _add_rk(s, w, rnd)
        s = _mix(s, inv=True)
    s = _shift(s, inv=True)
    s = _sub(s, inv=True)
    _add_rk(s, w, 0)
    return bytes(s)


def _pkcs7_pad(data, size=16):
    pad = size - (len(data) % size)
    return data + bytes([pad]) * pad


def _pkcs7_unpad(data):
    if not data or len(data) % 16:
        raise ValueError("bad length")
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad padding")
    return data[:-pad]


def aes_cbc_encrypt(key, iv, data):
    out = b""
    prev = iv
    for i in range(0, len(_pkcs7_pad(data)), 16):
        blk = bytes(a ^ b for a, b in zip(_pkcs7_pad(data)[i:i + 16], prev))
        prev = aes_encrypt_block(key, blk)
        out += prev
    return out


def aes_cbc_decrypt(key, iv, data):
    if len(data) % 16 or not data:
        raise ValueError("bad length")
    out = b""
    prev = iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(aes_decrypt_block(key, blk), prev))
        prev = blk
    return _pkcs7_unpad(out)


# --- AES-GCM (NIST SP 800-38D) ------------------------------------------------
def _ghash(h, aad, ct):
    def _pad16(b):
        return b + b"\x00" * ((-len(b)) % 16)

    def _mul128(x, y):
        # GF(2^128) with R = 11100001 || 0^120
        z = 0
        v = y
        for i in range(128):
            if (x >> (127 - i)) & 1:
                z ^= v
            if v & 1:
                v = (v >> 1) ^ 0xE1000000000000000000000000000000
            else:
                v >>= 1
        return z

    h_int = int.from_bytes(h, "big")
    data = _pad16(aad) + _pad16(ct)
    data += struct.pack(">QQ", len(aad) * 8, len(ct) * 8)
    y = 0
    for i in range(0, len(data), 16):
        y = _mul128(y ^ int.from_bytes(data[i:i + 16], "big"), h_int)
    return y.to_bytes(16, "big")


def aes_gcm_encrypt(key, nonce, plaintext, aad=b""):
    h = aes_encrypt_block(key, b"\x00" * 16)
    if len(nonce) != 12:
        raise ValueError("only 12-byte GCM nonce supported in this helper")
    j0 = nonce + b"\x00\x00\x00\x01"
    # CTR starting at inc32(J0)
    def _inc32(block):
        prefix, ctr = block[:12], struct.unpack(">I", block[12:])[0]
        return prefix + struct.pack(">I", (ctr + 1) & 0xFFFFFFFF)

    ctr = _inc32(j0)
    ct = b""
    for i in range(0, len(plaintext), 16):
        ks = aes_encrypt_block(key, ctr)
        chunk = plaintext[i:i + 16]
        ct += bytes(a ^ b for a, b in zip(chunk, ks))
        ctr = _inc32(ctr)
    s = _ghash(h, aad, ct)
    tag = bytes(a ^ b for a, b in zip(s, aes_encrypt_block(key, j0)))
    return ct, tag


def aes_gcm_decrypt(key, nonce, ciphertext, tag, aad=b""):
    h = aes_encrypt_block(key, b"\x00" * 16)
    if len(nonce) != 12:
        raise ValueError("only 12-byte GCM nonce supported in this helper")
    j0 = nonce + b"\x00\x00\x00\x01"
    s = _ghash(h, aad, ciphertext)
    expect = bytes(a ^ b for a, b in zip(s, aes_encrypt_block(key, j0)))
    if expect != tag:
        raise ValueError("bad GCM tag")

    def _inc32(block):
        prefix, ctr = block[:12], struct.unpack(">I", block[12:])[0]
        return prefix + struct.pack(">I", (ctr + 1) & 0xFFFFFFFF)

    ctr = _inc32(j0)
    pt = b""
    for i in range(0, len(ciphertext), 16):
        ks = aes_encrypt_block(key, ctr)
        chunk = ciphertext[i:i + 16]
        pt += bytes(a ^ b for a, b in zip(chunk, ks))
        ctr = _inc32(ctr)
    return pt


# --- XXTEA (delta configurable) ------------------------------------------------
def _xxtea_words(data, include_length):
    n = (len(data) + 3) // 4
    words = list(struct.unpack("<%dI" % n, data.ljust(n * 4, b"\x00")))
    if include_length:
        words.append(len(data))
    return words


def xxtea_encrypt(data, key, delta=0x9E3779B9):
    if len(key) != 16:
        raise ValueError("xxtea key must be 16 bytes")
    v = _xxtea_words(data, True)
    k = struct.unpack("<4I", key)
    n = len(v)
    if n < 2:
        return struct.pack("<%dI" % n, *v)
    rounds = 6 + 52 // n
    total = 0
    z = v[n - 1]
    for _ in range(rounds):
        total = (total + delta) & 0xFFFFFFFF
        e = (total >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            v[p] = (v[p] + (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)) ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z)))) & 0xFFFFFFFF
            z = v[p]
        y = v[0]
        v[n - 1] = (v[n - 1] + (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)) ^ ((total ^ y) + (k[((n - 1) & 3) ^ e] ^ z)))) & 0xFFFFFFFF
        z = v[n - 1]
    return struct.pack("<%dI" % n, *v)


def xxtea_decrypt(data, key, delta=0x9E3779B9):
    if len(data) % 4 or len(data) < 8:
        raise ValueError("bad xxtea length")
    if len(key) != 16:
        raise ValueError("xxtea key must be 16 bytes")
    v = list(struct.unpack("<%dI" % (len(data) // 4), data))
    k = struct.unpack("<4I", key)
    n = len(v)
    rounds = 6 + 52 // n
    total = (rounds * delta) & 0xFFFFFFFF
    y = v[0]
    for _ in range(rounds):
        e = (total >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)) ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z)))) & 0xFFFFFFFF
            y = v[p]
        z = v[n - 1]
        v[0] = (v[0] - (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)) ^ ((total ^ y) + (k[(0 & 3) ^ e] ^ z)))) & 0xFFFFFFFF
        y = v[0]
        total = (total - delta) & 0xFFFFFFFF
    raw = struct.pack("<%dI" % n, *v)
    length = v[n - 1]
    if length > len(raw) - 4 or length < 0:
        raise ValueError("bad xxtea length word")
    return raw[:length]


# --- Threefish-256 ---------------------------------------------------------------
_M64 = (1 << 64) - 1
_TF_ROT = ((14, 16), (52, 57), (23, 40), (5, 37), (25, 33), (46, 12), (58, 22), (32, 32))
_TF_PERM = (0, 3, 2, 1)


def _rotl64(x, n):
    return ((x << n) | (x >> (64 - n))) & _M64


def _rotr64(x, n):
    return ((x >> n) | (x << (64 - n))) & _M64


def _tf_key_schedule(key_words, tweak_words):
    k = list(key_words) + [0x1BD11BDAA9FC1A22 ^ key_words[0] ^ key_words[1] ^ key_words[2] ^ key_words[3]]
    t = list(tweak_words) + [tweak_words[0] ^ tweak_words[1]]
    ks = []
    for s in range(19):
        ks.append([
            k[s % 5],
            (k[(s + 1) % 5] + t[s % 3]) & _M64,
            (k[(s + 2) % 5] + t[(s + 1) % 3]) & _M64,
            (k[(s + 3) % 5] + s) & _M64,
        ])
    return ks


def threefish256_encrypt_block(key, tweak, block):
    v = list(struct.unpack("<4Q", block))
    ks = _tf_key_schedule(struct.unpack("<4Q", key), struct.unpack("<2Q", tweak))
    for d in range(72):
        if d % 4 == 0:
            s = d // 4
            v = [(v[i] + ks[s][i]) & _M64 for i in range(4)]
        r0, r1 = _TF_ROT[d % 8]
        v[0] = (v[0] + v[1]) & _M64
        v[1] = _rotl64(v[1], r0) ^ v[0]
        v[2] = (v[2] + v[3]) & _M64
        v[3] = _rotl64(v[3], r1) ^ v[2]
        v = [v[_TF_PERM[i]] for i in range(4)]
    v = [(v[i] + ks[18][i]) & _M64 for i in range(4)]
    return struct.pack("<4Q", *v)


def threefish256_decrypt_block(key, tweak, block):
    v = list(struct.unpack("<4Q", block))
    ks = _tf_key_schedule(struct.unpack("<4Q", key), struct.unpack("<2Q", tweak))
    v = [(v[i] - ks[18][i]) & _M64 for i in range(4)]
    for d in range(71, -1, -1):
        v = [v[_TF_PERM.index(i)] for i in range(4)]
        r0, r1 = _TF_ROT[d % 8]
        v[1] = _rotr64(v[1] ^ v[0], r0)
        v[0] = (v[0] - v[1]) & _M64
        v[3] = _rotr64(v[3] ^ v[2], r1)
        v[2] = (v[2] - v[3]) & _M64
        if d % 4 == 0:
            s = d // 4
            v = [(v[i] - ks[s][i]) & _M64 for i in range(4)]
    return struct.pack("<4Q", *v)
