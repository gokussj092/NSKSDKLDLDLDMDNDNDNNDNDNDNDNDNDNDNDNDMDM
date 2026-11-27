#!/usr/bin/env python3
"""Reimplementation of OpenVPNClient.j0() from ExoticFast VIP.

j0(s) = XXTEA-decrypt(standard_base64_decode(s), key="s!02a" padded to 16 bytes)
The XXTEA round function is n4/a.a (AbstractC2117a.a); byte<->int conversion
is n4/a.h / n4/a.g (little-endian, length appended on encrypt side).
Verified against the live catalog 2026-11-27 (Version 5.8).
"""
import base64

M32 = 0xFFFFFFFF


def to_i32(x):
    x &= M32
    return x - 0x100000000 if x >= 0x80000000 else x


def u32(x):
    return x & M32


DELTA = -1640531527  # 0x9E3779B9


def _mx(z, y, sum_, p, e, k):
    # n4/a.a(y?, ...): ((sum^y) + (k[(p&3)^e]^z)) ^ (((z>>>5)^(y<<2)) + ((y>>>3)^(z<<4)))
    # call order in j0: a(sum, z, y, p, e, k) -> i3=sum, i6=z?? -- see note below
    # Resolved empirically: standard XXTEA MX with (y=v[p], z=v[p-1]):
    a = to_i32(to_i32(sum_ ^ y) + to_i32(k[(p & 3) ^ e] ^ z))
    b = to_i32(to_i32((u32(z) >> 5) ^ to_i32(y << 2)) + to_i32((u32(y) >> 3) ^ to_i32(z << 4)))
    return to_i32(a ^ b)


def _h(data, include_length):
    n = (len(data) + 3) // 4
    v = [0] * (n + 1) if include_length else [0] * n
    if include_length:
        v[n] = len(data)
    for i, b in enumerate(data):
        v[i >> 2] |= (b & 0xFF) << ((i & 3) << 3)
    return v


def _g(v, include_length):
    n = len(v) << 2
    if include_length:
        m = v[-1]
        if m < n - 7 or m > n - 4:
            return None
        n = m
    out = bytearray(n)
    for i in range(n):
        out[i] = (u32(v[i >> 2]) >> ((i & 3) << 3)) & 0xFF
    return bytes(out)


def _key_ints():
    key = b"s!02a"
    kb = bytearray(16)
    kb[:len(key)] = key
    return _h(bytes(kb), False)


def xxtea_encrypt(data: bytes) -> bytes:
    k = _key_ints()
    v = _h(data, True)
    n = len(v)
    if n < 2:
        return _g(v, False)
    rounds = 6 + 52 // n
    sum_ = 0
    z = v[n - 1]
    for _ in range(rounds):
        sum_ = to_i32(sum_ + DELTA)
        e = (u32(sum_) >> 2) & 3
        for p in range(n):
            y = v[(p + 1) % n]
            v[p] = to_i32(v[p] + _mx(z, y, sum_, p, e, k))
            z = v[p]
    return _g(v, False)


def xxtea_decrypt(data: bytes) -> bytes:
    k = _key_ints()
    v = _h(data, False)
    n = len(v)
    if n < 2:
        return _g(v, False)
    rounds = 6 + 52 // n
    sum_ = to_i32(rounds * DELTA)
    y = v[0]
    while sum_ != 0:
        e = (u32(sum_) >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = to_i32(v[p] - _mx(z, y, sum_, p, e, k))
            y = v[p]
        z = v[n - 1]
        v[0] = to_i32(v[0] - _mx(z, y, sum_, 0, e, k))
        y = v[0]
        sum_ = to_i32(sum_ - DELTA)
    return _g(v, True)


def j0(s: str) -> str:
    """OpenVPNClient.j0: decrypt a j0-encoded field. Empty input -> ''."""
    if not s:
        return ""
    try:
        raw = base64.b64decode(s)
    except Exception:
        return ""
    if not raw:
        return ""
    pt = xxtea_decrypt(raw)
    if pt is None:
        return ""
    return pt.decode("utf-8", errors="replace")


def l0(s: str) -> str:
    """OpenVPNClient.l0: encrypt a field (inverse of j0)."""
    raw = xxtea_encrypt(s.encode("utf-8"))
    return base64.b64encode(raw).decode("ascii")


if __name__ == "__main__":
    # round-trip self-test
    for txt in ["hello world", "192.168.1.1", "CONNECT [host] HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "sshuser", "p@ssw0rd!", "Test Payload with [host] and JX markers"]:
        enc = l0(txt)
        dec = j0(enc)
        print(repr(txt), "->", enc, "->", repr(dec), "OK" if dec == txt else "MISMATCH")
    # live sample from catalog v5.8
    print("live sample:", repr(j0("vVyHlokb1/jzbMVH50/wotv2+nT8WZOfwhaGrw==")))
