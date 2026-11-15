"""AES-256 (solo cifrado de bloque) + GHASH/GCM en Python puro.

Fallback documentado para JK VPN cuando pycryptodome no esta disponible.
Validado contra pycryptodome con el catalogo real (61 segmentos) y contra
el vector NIST GCM Test Case 3 (AES-256, nonce 12 B, sin AAD).
"""
import struct

# --- GF(2^8) con polinomio 0x11b ---
def _gf_mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = ((a << 1) ^ 0x11b) & 0xff if a & 0x80 else (a << 1)
        b >>= 1
    return r

def _gf_pow(a, e):
    r = 1
    while e:
        if e & 1:
            r = _gf_mul(r, a)
        a = _gf_mul(a, a)
        e >>= 1
    return r

def _make_sbox():
    sbox = []
    for i in range(256):
        inv = 0 if i == 0 else _gf_pow(i, 254)
        s = inv
        for shift in (1, 2, 3, 4):
            s ^= ((inv << shift) | (inv >> (8 - shift))) & 0xff
        sbox.append((s ^ 0x63) & 0xff)
    return sbox

_SBOX = _make_sbox()
# T-tables (Te0..Te3) para cifrado rapido
def _make_ttables():
    te = [[0] * 256 for _ in range(4)]
    for i in range(256):
        s = _SBOX[i]
        s2 = _gf_mul(s, 2)
        s3 = _gf_mul(s, 3)
        te[0][i] = (s2 << 24) | (s << 16) | (s << 8) | s3
        te[1][i] = (s3 << 24) | (s2 << 16) | (s << 8) | s
        te[2][i] = (s << 24) | (s3 << 16) | (s2 << 8) | s
        te[3][i] = (s << 24) | (s << 16) | (s3 << 8) | s2
    return te

_TE = _make_ttables()
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
         0x6c, 0xd8, 0xab, 0x4d]

class AES256:
    """AES-256, solo cifrado (suficiente para GCM)."""

    def __init__(self, key):
        assert len(key) == 32
        w = [int.from_bytes(key[i:i + 4], 'big') for i in range(0, 32, 4)]
        for i in range(8, 60):
            t = w[i - 1]
            if i % 8 == 0:
                t = (_SBOX[(t >> 16) & 0xff] << 24 | _SBOX[(t >> 8) & 0xff] << 16 |
                     _SBOX[t & 0xff] << 8 | _SBOX[(t >> 24) & 0xff]) ^ (_RCON[i // 8 - 1] << 24)
            elif i % 8 == 4:
                t = (_SBOX[(t >> 24) & 0xff] << 24 | _SBOX[(t >> 16) & 0xff] << 16 |
                     _SBOX[(t >> 8) & 0xff] << 8 | _SBOX[t & 0xff])
            w.append(w[i - 8] ^ t)
        self._rk = w  # 60 words

    def encrypt_block(self, block):
        assert len(block) == 16
        s = [int.from_bytes(block[i:i + 4], 'big') for i in range(0, 16, 4)]
        rk = self._rk
        for i in range(4):
            s[i] ^= rk[i]
        for rnd in range(1, 14):
            t = [0, 0, 0, 0]
            t[0] = (_TE[0][(s[0] >> 24) & 0xff] ^ _TE[1][(s[1] >> 16) & 0xff] ^
                    _TE[2][(s[2] >> 8) & 0xff] ^ _TE[3][s[3] & 0xff] ^ rk[rnd * 4])
            t[1] = (_TE[0][(s[1] >> 24) & 0xff] ^ _TE[1][(s[2] >> 16) & 0xff] ^
                    _TE[2][(s[3] >> 8) & 0xff] ^ _TE[3][s[0] & 0xff] ^ rk[rnd * 4 + 1])
            t[2] = (_TE[0][(s[2] >> 24) & 0xff] ^ _TE[1][(s[3] >> 16) & 0xff] ^
                    _TE[2][(s[0] >> 8) & 0xff] ^ _TE[3][s[1] & 0xff] ^ rk[rnd * 4 + 2])
            t[3] = (_TE[0][(s[3] >> 24) & 0xff] ^ _TE[1][(s[0] >> 16) & 0xff] ^
                    _TE[2][(s[1] >> 8) & 0xff] ^ _TE[3][s[2] & 0xff] ^ rk[rnd * 4 + 3])
            s = t
        # ronda final: SubBytes + ShiftRows + AddRoundKey
        out = bytearray(16)
        for i in range(4):
            word = rk[56 + i]
            for j in range(4):
                out[4 * i + j] = _SBOX[(s[(i + j) % 4] >> (24 - 8 * j)) & 0xff] ^ ((word >> (24 - 8 * j)) & 0xff)
        return bytes(out)

# --- GHASH ---
def _ghash(h, data):
    # data con longitud multiplo de 16
    y = 0
    h_int = int.from_bytes(h, 'big')
    for i in range(0, len(data), 16):
        y ^= int.from_bytes(data[i:i + 16], 'big')
        # multiplicacion en GF(2^128), polinomio x^128+x^7+x^2+x+1 (R);
        # se procesan los bits de y de MSB a LSB (NIST SP 800-38D, alg. 1)
        z = 0
        v = h_int
        x = y
        for bit in range(128):
            if (x >> (127 - bit)) & 1:
                z ^= v
            if v & 1:
                v = (v >> 1) ^ 0xe1000000000000000000000000000000
            else:
                v >>= 1
        y = z
    return y.to_bytes(16, 'big')

def gcm_decrypt_pure(key, nonce, ciphertext_and_tag, aad=b''):
    """AES-256-GCM decrypt (nonce 12 B). Devuelve plaintext o lanza ValueError."""
    assert len(nonce) == 12
    assert len(ciphertext_and_tag) >= 16
    ct, tag = ciphertext_and_tag[:-16], ciphertext_and_tag[-16:]
    aes = AES256(key)
    h = aes.encrypt_block(b'\x00' * 16)
    j0 = nonce + b'\x00\x00\x00\x01'
    # keystream CTR desde inc32(J0)
    pt = bytearray()
    counter = int.from_bytes(j0, 'big')
    for i in range(0, len(ct), 16):
        counter += 1
        ks = aes.encrypt_block(counter.to_bytes(16, 'big'))
        block = ct[i:i + 16]
        pt += bytes(a ^ b for a, b in zip(block, ks))
    # GHASH: AAD || CT || len(AAD)||len(CT) en bits
    def pad16(b):
        return b + b'\x00' * ((-len(b)) % 16)
    s = _ghash(h, pad16(aad) + pad16(ct) +
               struct.pack('>QQ', len(aad) * 8, len(ct) * 8))
    calc = bytes(a ^ b for a, b in zip(s, aes.encrypt_block(j0)))
    if calc != tag:
        raise ValueError('GCM tag no coincide')
    return bytes(pt)

def gcm_encrypt_pure(key, nonce, plaintext, aad=b''):
    """AES-256-GCM encrypt (nonce 12 B). Devuelve ciphertext || tag(16)."""
    assert len(nonce) == 12
    aes = AES256(key)
    h = aes.encrypt_block(b'\x00' * 16)
    j0 = nonce + b'\x00\x00\x00\x01'
    ct = bytearray()
    counter = int.from_bytes(j0, 'big')
    for i in range(0, len(plaintext), 16):
        counter += 1
        ks = aes.encrypt_block(counter.to_bytes(16, 'big'))
        block = plaintext[i:i + 16]
        ct += bytes(a ^ b for a, b in zip(block, ks))
    def pad16(b):
        return b + b'\x00' * ((-len(b)) % 16)
    s = _ghash(h, pad16(aad) + pad16(bytes(ct)) +
               struct.pack('>QQ', len(aad) * 8, len(ct) * 8))
    tag = bytes(a ^ b for a, b in zip(s, aes.encrypt_block(j0)))
    return bytes(ct) + tag
