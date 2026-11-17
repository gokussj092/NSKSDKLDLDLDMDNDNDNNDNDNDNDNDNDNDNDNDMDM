"""Generic XXTEA (last-word length variant), test-only.

Pure-Python reference used by this dossier's tests with TEST keys only.
No format keys, no endpoints, no real data. The operational script
(MO_VPN.py) carries the real implementation and constants; the real-key
decryption is covered by its --self-test (see RESULTS.md).
"""
from __future__ import annotations

import struct

MASK = 0xFFFFFFFF


def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def _mx(total: int, y: int, z: int, p: int, e: int, k: list) -> int:
    a = _u32(((_u32(z >> 5) ^ _u32(y << 2)) + _u32(_u32(y >> 3) ^ _u32(z << 4))))
    b = _u32(_u32(total ^ y) + _u32(k[(p & 3) ^ e] ^ z))
    return _u32(a ^ b)


def _fix_key(key: bytes) -> bytes:
    if len(key) == 16:
        return key
    if len(key) < 16:
        return key + b"\x00" * (16 - len(key))
    return key[:16]


def xxtea_encrypt(data: bytes, key: bytes, delta: int) -> bytes:
    n_words = (len(data) + 3) // 4
    v = list(struct.unpack("<%dI" % n_words, data + b"\x00" * (n_words * 4 - len(data))))
    v.append(len(data))
    k = list(struct.unpack("<4I", _fix_key(key)))
    n = len(v)
    rounds = 6 + 52 // n
    total = 0
    z = v[n - 1]
    for _ in range(rounds):
        total = _u32(total + delta)
        e = (total >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            z = _u32(v[p] + _mx(total, y, z, p, e, k))
            v[p] = z
        y = v[0]
        z = _u32(v[n - 1] + _mx(total, y, z, n - 1, e, k))
        v[n - 1] = z
    return struct.pack("<%dI" % n, *v)


def xxtea_decrypt(data: bytes, key: bytes, delta: int):
    """Decrypt; returns None when the embedded length is inconsistent."""
    if not data:
        return b""
    n_words = len(data) // 4
    v = list(struct.unpack("<%dI" % n_words, data))
    k = list(struct.unpack("<4I", _fix_key(key)))
    n = len(v)
    if n < 2:
        return None
    rounds = 6 + 52 // n
    total = _u32(rounds * delta)
    y = v[0]
    while total != 0:
        e = (total >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            y = _u32(v[p] - _mx(total, y, z, p, e, k))
            v[p] = y
        z = v[n - 1]
        y = _u32(v[0] - _mx(total, y, z, 0, e, k))
        v[0] = y
        total = _u32(total - delta)
    total_bytes = len(v) << 2
    length = v[-1]
    if length < total_bytes - 7 or length > total_bytes - 4:
        return None
    return struct.pack("<%dI" % len(v), *v)[:length]
