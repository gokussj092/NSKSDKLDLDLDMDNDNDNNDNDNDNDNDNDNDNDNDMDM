"""Criptografia generica extraida de WyrVPN.py (AES-GCM + sobre v01).

Sin claves de formato, sin endpoints, sin tokens. Las claves de prueba
las aporta quien llama (ver tests/test_method.py). Origen: script
operativo ~/workspace/catalogs/wyrvpn/WyrVPN.py (SHA-256 en MANIFEST.json).
"""
import base64
import os
import struct

class DecodeError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------- AES-128/256-GCM
# Python puro. Solo se necesita cifrado de bloques (GCM usa CTR + GHASH).
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
                    aa = ((aa << 1) ^ (0x1B if aa & 0x80 else 0)) & 0xFF
                    bb >>= 1
                if p == 1:
                    inv = y
                    break
        s = inv ^ ((inv << 1) | (inv >> 7)) ^ ((inv << 2) | (inv >> 6)) \
            ^ ((inv << 3) | (inv >> 5)) ^ ((inv << 4) | (inv >> 4)) ^ 0x63
        sbox.append(s & 0xFF)
    return sbox


_SBOX = _make_sbox()
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
         0x6C, 0xD8, 0xAB, 0x4D]
_GCM_R = 0xE1000000000000000000000000000000


def _aes_key_expand(key):
    """Expansion de clave AES. Devuelve (palabras, rondas). Acepta 16/24/32 B."""
    if len(key) not in (16, 24, 32):
        raise ValueError("clave AES de 16, 24 o 32 bytes")
    nk = len(key) // 4
    nr = nk + 6
    w = list(struct.unpack(">%dI" % nk, key))
    for i in range(nk, 4 * (nr + 1)):
        temp = w[i - 1]
        if i % nk == 0:
            rot = ((temp << 8) | (temp >> 24)) & 0xFFFFFFFF
            sub = (_SBOX[(rot >> 24) & 0xFF] << 24) | (_SBOX[(rot >> 16) & 0xFF] << 16) \
                | (_SBOX[(rot >> 8) & 0xFF] << 8) | _SBOX[rot & 0xFF]
            temp = sub ^ (_RCON[i // nk - 1] << 24)
        elif nk > 6 and i % nk == 4:
            temp = (_SBOX[(temp >> 24) & 0xFF] << 24) | (_SBOX[(temp >> 16) & 0xFF] << 16) \
                | (_SBOX[(temp >> 8) & 0xFF] << 8) | _SBOX[temp & 0xFF]
        w.append(w[i - nk] ^ temp)
    return w, nr


def _aes_encrypt_block(key_words, nr, block):
    s = list(struct.unpack(">4I", block))
    rk = key_words
    for i in range(4):
        s[i] ^= rk[i]
    for rnd in range(1, nr):
        b = bytearray(16)
        for i in range(4):
            for j in range(4):
                b[4 * j + i] = _SBOX[(s[j] >> (24 - 8 * i)) & 0xFF]
        sb = bytearray(16)
        for r in range(4):
            for c in range(4):
                sb[4 * c + r] = b[4 * ((c + r) % 4) + r]

        def xtime(x):
            return ((x << 1) ^ (0x1B if x & 0x80 else 0)) & 0xFF
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
            b[4 * j + i] = _SBOX[(s[j] >> (24 - 8 * i)) & 0xFF]
    sb = bytearray(16)
    for r in range(4):
        for c in range(4):
            sb[4 * c + r] = b[4 * ((c + r) % 4) + r]
    s = list(struct.unpack(">4I", bytes(sb)))
    for i in range(4):
        s[i] ^= rk[4 * nr + i]
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
    """AES-GCM decrypt (Python puro). nonce: 12 bytes. tag: 16 bytes."""
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
    """AES-GCM encrypt (Python puro). Devuelve (ciphertext, tag)."""
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
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


# ------------------------------------------------------------ sobre v01
def v01_encrypt(plain, key):
    """Sobre v01: Base64("v01" || nonce[12] || AES-GCM(ct || tag))."""
    nonce = os.urandom(12)
    ct, tag = _aes_gcm_encrypt(key, nonce, plain)
    return base64.b64encode(b"v01" + nonce + ct + tag).decode()


def v01_decrypt(b64, key):
    """Abre un sobre v01 -> bytes. Lanza DecodeError si el tag no verifica."""
    try:
        raw = base64.b64decode(b64, validate=False)
    except Exception as exc:
        raise DecodeError("V01_BASE64", "sobre v01 con Base64 invalido") from exc
    if len(raw) < 3 + 12 + 16 or raw[:3] != b"v01":
        raise DecodeError("V01_MAGIC", "el sobre no empieza por 'v01'")
    try:
        return _aes_gcm_decrypt(key, raw[3:15], raw[15:-16], raw[-16:])
    except ValueError as exc:
        raise DecodeError("V01_TAG", "el tag GCM no verifica con esta clave") from exc


# ------------------------------------------------------------ peticion sync
