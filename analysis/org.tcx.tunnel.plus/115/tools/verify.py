#!/usr/bin/env python3
"""Synthetic-only verifier/test support for this dossier.

All keys are TEST-ONLY constants (bytes(range(...))). No real format keys,
no real credentials, no download endpoints, no network access.
"""
"""Sanitized verifier for the TCx Tunnel Plus method.

Reproduces the format logic with TEST-ONLY keys over the synthetic fixture
in tests/fixtures/. No network, no real keys, no real profiles.

Usage:  python3 tools/verify.py
"""
import base64
import hashlib
import hmac
import json
import struct
import sys
from pathlib import Path

"""Crypto core for synthetic test vectors (test-only keys, no real material).
Validated against `openssl enc -aes-256-cbc` for CBC; GCM by round-trip + tag check.
"""
import hashlib, hmac as hmac_mod, struct

# ---- GF(2^8) ----
def _gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi: a ^= 0x1B
        b >>= 1
    return p

def _gf_pow(a, e):
    r = 1
    while e:
        if e & 1: r = _gf_mul(r, a)
        a = _gf_mul(a, a); e >>= 1
    return r

_SBOX = []
_INV_SBOX = [0]*256
for _i in range(256):
    _inv = 0 if _i == 0 else _gf_pow(_i, 254)
    _s = _inv
    for _sh in (1, 2, 3, 4):
        _s ^= ((_inv << _sh) | (_inv >> (8-_sh))) & 0xFF
    _s ^= 0x63
    _SBOX.append(_s & 0xFF)
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_RCON = [1,2,4,8,16,32,64,128,27,54,108,216,171,77,154,47]

def _key_expand(key):
    nk = len(key)//4
    nr = nk + 6
    w = [list(key[4*i:4*i+4]) for i in range(nk)]
    for i in range(nk, 4*(nr+1)):
        t = list(w[i-1])
        if i % nk == 0:
            t = t[1:]+t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i//nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i-nk], t)])
    return w, nr

def _add_rk(s, w, rnd):
    for c in range(4):
        for r in range(4):
            s[4*c+r] ^= w[4*rnd+c][r]
    return s

def aes_encrypt_block(key, block):
    w, nr = _key_expand(key)
    s = bytearray(block)
    _add_rk(s, w, 0)
    for rnd in range(1, nr):
        t = bytearray(16)
        for r in range(4):
            for c in range(4):
                t[4*c+r] = _SBOX[s[4*((c+r) % 4)+r]]
        s = t
        t = bytearray(16)
        for c in range(4):
            a0,a1,a2,a3 = s[4*c], s[4*c+1], s[4*c+2], s[4*c+3]
            t[4*c]   = _gf_mul(a0,2)^_gf_mul(a1,3)^a2^a3
            t[4*c+1] = a0^_gf_mul(a1,2)^_gf_mul(a2,3)^a3
            t[4*c+2] = a0^a1^_gf_mul(a2,2)^_gf_mul(a3,3)
            t[4*c+3] = _gf_mul(a0,3)^a1^a2^_gf_mul(a3,2)
        s = t
        _add_rk(s, w, rnd)
    t = bytearray(16)
    for r in range(4):
        for c in range(4):
            t[4*c+r] = _SBOX[s[4*((c+r) % 4)+r]]
    s = t
    _add_rk(s, w, nr)
    return bytes(s)

def aes_decrypt_block(key, block):
    w, nr = _key_expand(key)
    s = bytearray(block)
    _add_rk(s, w, nr)
    for rnd in range(nr-1, 0, -1):
        t = bytearray(16)
        for r in range(4):
            for c in range(4):
                t[4*c+r] = _INV_SBOX[s[4*((c-r) % 4)+r]]
        s = t
        _add_rk(s, w, rnd)
        t = bytearray(16)
        for c in range(4):
            a0,a1,a2,a3 = s[4*c], s[4*c+1], s[4*c+2], s[4*c+3]
            t[4*c]   = _gf_mul(a0,14)^_gf_mul(a1,11)^_gf_mul(a2,13)^_gf_mul(a3,9)
            t[4*c+1] = _gf_mul(a0,9)^_gf_mul(a1,14)^_gf_mul(a2,11)^_gf_mul(a3,13)
            t[4*c+2] = _gf_mul(a0,13)^_gf_mul(a1,9)^_gf_mul(a2,14)^_gf_mul(a3,11)
            t[4*c+3] = _gf_mul(a0,11)^_gf_mul(a1,13)^_gf_mul(a2,9)^_gf_mul(a3,14)
        s = t
    t = bytearray(16)
    for r in range(4):
        for c in range(4):
            t[4*c+r] = _INV_SBOX[s[4*((c-r) % 4)+r]]
    s = t
    _add_rk(s, w, 0)
    return bytes(s)

def _pkcs7_pad(data):
    p = 16 - len(data) % 16
    return data + bytes([p])*p

def _pkcs7_unpad(data):
    if not data or len(data) % 16: raise ValueError("bad length")
    p = data[-1]
    if p < 1 or p > 16 or data[-p:] != bytes([p])*p: raise ValueError("bad padding")
    return data[:-p]

def aes_cbc_encrypt(key, iv, data):
    data = _pkcs7_pad(data)
    out = bytearray(); prev = iv
    for off in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[off:off+16], prev))
        enc = aes_encrypt_block(key, blk)
        out.extend(enc); prev = enc
    return bytes(out)

def aes_cbc_decrypt(key, iv, data):
    if len(data) % 16: raise ValueError("bad length")
    out = bytearray(); prev = iv
    for off in range(0, len(data), 16):
        dec = aes_decrypt_block(key, data[off:off+16])
        out.extend(bytes(a ^ b for a, b in zip(dec, prev)))
        prev = data[off:off+16]
    return _pkcs7_unpad(bytes(out))

# ---- GCM ----
def _ghash(h, data):
    # data length must be multiple of 16
    y = 0
    for off in range(0, len(data), 16):
        blk = int.from_bytes(data[off:off+16], "big")
        y ^= blk
        # GF(2^128) multiply y * h (GCM polynomial)
        z = 0; v = h
        yy = y
        for _ in range(128):
            if yy & 1: z ^= v
            if v & 1:
                v = (v >> 1) ^ 0xE1000000000000000000000000000000
            else:
                v >>= 1
            yy >>= 1
        y = z
    return y

def _gctr(key, icb, data):
    out = bytearray()
    ctr = int.from_bytes(icb, "big")
    for off in range(0, len(data), 16):
        ks = aes_encrypt_block(key, ctr.to_bytes(16, "big"))
        chunk = data[off:off+16]
        out.extend(bytes(a ^ b for a, b in zip(chunk, ks)))
        ctr = (ctr + 1) & ((1 << 128) - 1)
    return bytes(out)

def aes_gcm_encrypt(key, nonce12, plaintext, aad=b""):
    h = int.from_bytes(aes_encrypt_block(key, b"\x00"*16), "big")
    j0 = nonce12 + b"\x00\x00\x00\x01"
    ct = _gctr(key, nonce12 + b"\x00\x00\x00\x02", plaintext)
    def _pad16(b):
        return b + b"\x00" * ((-len(b)) % 16)
    s = _ghash(h, _pad16(aad) + _pad16(ct) + (len(aad)*8).to_bytes(8, "big") + (len(ct)*8).to_bytes(8, "big"))
    tag = bytes(a ^ b for a, b in zip(aes_encrypt_block(key, j0), s.to_bytes(16, "big")))
    return ct, tag

def aes_gcm_decrypt(key, nonce12, ct, tag, aad=b""):
    h = int.from_bytes(aes_encrypt_block(key, b"\x00"*16), "big")
    j0 = nonce12 + b"\x00\x00\x00\x01"
    def _pad16(b):
        return b + b"\x00" * ((-len(b)) % 16)
    s = _ghash(h, _pad16(aad) + _pad16(ct) + (len(aad)*8).to_bytes(8, "big") + (len(ct)*8).to_bytes(8, "big"))
    expect = bytes(a ^ b for a, b in zip(aes_encrypt_block(key, j0), s.to_bytes(16, "big")))
    if not hmac_mod.compare_digest(expect, tag):
        raise ValueError("GCM tag mismatch")
    return _gctr(key, nonce12 + b"\x00\x00\x00\x02", ct)

# ---- XXTEA (btea, length word) ----
def xxtea_encrypt(data, key16, delta=0x9E3779B9):
    k = struct.unpack("<4I", key16)
    n = (len(data) + 3)//4
    v = list(struct.unpack("<%dI" % n, data + b"\x00"*(n*4-len(data)))) + [len(data)]
    n = len(v)
    if n > 1:
        rounds = 6 + 52//n
        ssum = 0; z = v[n-1]
        for _ in range(rounds):
            ssum = (ssum + delta) & 0xFFFFFFFF
            e = (ssum >> 2) & 3
            for p in range(n-1):
                y = v[p+1]
                mx = ((((z>>5)^(y<<2))+((y>>3)^(z<<4))) ^ ((ssum^y)+(k[(p&3)^e]^z))) & 0xFFFFFFFF
                v[p] = (v[p]+mx) & 0xFFFFFFFF; z = v[p]
            y = v[0]
            mx = ((((z>>5)^(y<<2))+((y>>3)^(z<<4))) ^ ((ssum^y)+(k[((n-1)&3)^e]^z))) & 0xFFFFFFFF
            v[n-1] = (v[n-1]+mx) & 0xFFFFFFFF; z = v[n-1]
    return struct.pack("<%dI" % n, *v)

def xxtea_decrypt(data, key16, delta=0x9E3779B9):
    if len(data) % 4: raise ValueError("XXTEA input length must be multiple of 4")
    k = struct.unpack("<4I", key16)
    v = list(struct.unpack("<%dI" % (len(data)//4), data))
    n = len(v)
    if n > 1:
        rounds = 6 + 52//n
        ssum = (rounds * delta) & 0xFFFFFFFF
        y = v[0]
        for _ in range(rounds):
            e = (ssum >> 2) & 3
            for p in range(n-1, 0, -1):
                z = v[p-1]
                mx = ((((z>>5)^(y<<2))+((y>>3)^(z<<4))) ^ ((ssum^y)+(k[(p&3)^e]^z))) & 0xFFFFFFFF
                v[p] = (v[p]-mx) & 0xFFFFFFFF; y = v[p]
            z = v[n-1]
            mx = ((((z>>5)^(y<<2))+((y>>3)^(z<<4))) ^ ((ssum^y)+(k[(0&3)^e]^z))) & 0xFFFFFFFF
            v[0] = (v[0]-mx) & 0xFFFFFFFF; y = v[0]
            ssum = (ssum - delta) & 0xFFFFFFFF
    plain = struct.pack("<%dI" % n, *v)
    ln = v[n-1]
    if ln < 0 or ln > len(plain) - 4: raise ValueError("XXTEA length word out of range")
    return plain[:ln]



TEST_SEED = b"TEST-ONLY-SEED"  # TEST-ONLY (real seed = SHA-256 hex of the APK signing cert)
PREFIX = "tcxtunnelplus://"

def _key(seed=TEST_SEED):
    return hashlib.sha256(seed).digest()[:16]

def body_encrypt(plain, seed=TEST_SEED):
    """Body = Base64( XXTEA( AES-128-CBC( JSON ) ) ), IV 16 zeros, PKCS#7."""
    key = _key(seed)
    ct = aes_cbc_encrypt(key, b"\x00" * 16, plain)
    return base64.b64encode(xxtea_encrypt(ct, key)).decode()

def body_decrypt(text, seed=TEST_SEED):
    try:
        raw = base64.b64decode(text, validate=True)
    except Exception as exc:
        raise ValueError("bad base64") from exc
    key = _key(seed)
    inner = xxtea_decrypt(raw, key)
    return aes_cbc_decrypt(key, b"\x00" * 16, inner)

def tcx_wrap(body_b64):
    return PREFIX + body_b64

def tcx_unwrap(text, seed=TEST_SEED):
    if not isinstance(text, str) or not text.startswith(PREFIX):
        raise ValueError("missing tcxtunnelplus:// prefix")
    return body_decrypt(text[len(PREFIX):], seed)

FIXTURE_NAME = "tcx_fixture.json"

def run_checks(fx):
    out = []
    try:
        out.append(("fixture body decrypts", json.loads(body_decrypt(fx["body_b64"])) == fx["plaintext"]))
    except Exception:
        out.append(("fixture body decrypts", False))
    try:
        out.append(("tcx:// text opens", json.loads(tcx_unwrap(fx["tcx_text"])) == fx["plaintext"]))
    except Exception:
        out.append(("tcx:// text opens", False))
    try:
        tcx_unwrap(fx["body_b64"]); out.append(("missing prefix rejected", False))
    except ValueError:
        out.append(("missing prefix rejected", True))
    return out

def main():
    fx_path = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / FIXTURE_NAME
    fx = json.loads(fx_path.read_text())
    checks = run_checks(fx)
    failed = [name for name, ok in checks if not ok]
    for name, ok in checks:
        print(("OK  " if ok else "FAIL") + " " + name)
    if failed:
        print("FAILED: %d check(s)" % len(failed))
        return 1
    print("All %d synthetic checks passed (TEST-ONLY keys, no network)." % len(checks))
    return 0

if __name__ == "__main__":
    sys.exit(main())
