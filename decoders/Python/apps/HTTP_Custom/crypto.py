"""HCX4/n11 SHA-256 HMAC prestates recovered from build 899's native engine.

The native engine embeds the SHA-256 states after its fixed HMAC ipad/opad
blocks, rather than exporting an HMAC key. Continue those states exactly;
ordinary hashlib.sha256(root + seed) is a different derivation. No APK, native
library, emulation, or network is needed at runtime.
"""
from __future__ import annotations
import struct

SHA256_CONSTANTS = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
)
MASK = 0xffffffff

def _rotate_right(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & MASK


def sha256_from_state(state: tuple[int, ...], data: bytes, previous_bytes: int = 64) -> bytes:
    """Finish SHA-256 after an integral number of previously compressed blocks."""
    length = previous_bytes + len(data)
    padded = data + b"\x80" + b"\0" * ((55 - length) % 64) + struct.pack(">Q", length * 8)
    state = list(state)
    rotate = _rotate_right
    for offset in range(0, len(padded), 64):
        words = list(struct.unpack(">16I", padded[offset:offset + 64]))
        for index in range(16, 64):
            x, y = words[index - 15], words[index - 2]
            small0 = rotate(x, 7) ^ rotate(x, 18) ^ (x >> 3)
            small1 = rotate(y, 17) ^ rotate(y, 19) ^ (y >> 10)
            words.append((words[index - 16] + small0 + words[index - 7] + small1) & MASK)
        a, b, c, d, e, f, g, h = state
        for index in range(64):
            big1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25)
            choose = (e & f) ^ (~e & g)
            temp1 = (h + big1 + choose + SHA256_CONSTANTS[index] + words[index]) & MASK
            big0 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (big0 + majority) & MASK
            a, b, c, d, e, f, g, h = (temp1 + temp2) & MASK, a, b, c, (d + temp1) & MASK, e, f, g
        state = [(x + y) & MASK for x, y in zip(state, (a, b, c, d, e, f, g, h))]
    return struct.pack(">8I", *state)


INNER_STATE = (0x82515a9a, 0xf6ec05fc, 0xf650b6cd, 0x523f8ce6,
               0xedf419ec, 0x1d6d6573, 0x66ff1b89, 0xf40a0181)
OUTER_STATE = (0x82185b01, 0x35cb48be, 0xdb6c3846, 0xbd714ec5,
               0x627728af, 0xdbaae4db, 0x463fbf8d, 0x88a24381)
CERT_SHA256 = bytes.fromhex(
    "95dd433d7e4a0be02d55cc62553edcfc8f077fe780be5a7da7f861c2558dc181"
)


def native_fold(data: bytes) -> bytes:
    """HMAC-prestate continuation over E9 || certificateSHA256 || data."""
    return sha256_from_state(OUTER_STATE, sha256_from_state(INNER_STATE, b"\xe9" + CERT_SHA256 + data))
