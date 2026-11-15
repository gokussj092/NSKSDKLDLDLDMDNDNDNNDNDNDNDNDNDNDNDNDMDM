#!/usr/bin/env python3
"""Ac Tunnel VPN — synthetic round-trip verifier for this dossier.

Stdlib only (+ tools/crypto_pure.py in this directory). No network, no
secrets: every key below is a SYNTHETIC test key generated in this file.
It proves the implemented layers round-trip; it does NOT prove compatibility
with a real app file (that needs the operational script and a real sample).
Run: python3 tools/verify.py
"""
import base64
import hashlib
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypto_pure import (  # noqa: E402
    aes_cbc_decrypt, aes_cbc_encrypt, aes_gcm_decrypt, aes_gcm_encrypt,
    threefish256_decrypt_block, threefish256_encrypt_block,
    xxtea_decrypt, xxtea_encrypt,
)

TEST_KEY = hashlib.sha256(b"TEST-ONLY-SYNTHETIC-KEY -- never a real key").digest()
TEST_KEY16 = TEST_KEY[:16]
TEST_IV = b"TEST-IV-16-BYTES"


def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        raise SystemExit(1)
    return cond


DELTA = 0x7A56D3E1
PT = json.dumps({"Version": "9.9-test", "Name": "TEST NETWORK",
                 "SNI": "www.example.org"}, ensure_ascii=False).encode("utf-8")


def _minus2(data):
    return bytes((b - 2) & 0xFF for b in data)


def _plus2(data):
    return bytes((b + 2) & 0xFF for b in data)


def mode0_encrypt(pt):
    inner = xxtea_encrypt(_plus2(pt), TEST_KEY16, DELTA)
    return base64.b64encode(aes_cbc_encrypt(TEST_KEY16, TEST_IV, inner)).decode()


def mode0_decrypt(b64):
    inner = aes_cbc_decrypt(TEST_KEY16, TEST_IV, base64.b64decode(b64))
    return _minus2(xxtea_decrypt(inner, TEST_KEY16, DELTA))


def mode2_key():
    return hashlib.pbkdf2_hmac("sha256", b"TEST-ONLY-SYNTHETIC-SEED",
                               b"TEST-ONLY-FIXED-SALT", 100000, 32)


def main():
    b64 = mode0_encrypt(PT)
    check("mode0 round-trip (AES-128-CBC + XXTEA delta 0x7A56D3E1 + minus-2)",
          mode0_decrypt(b64) == PT)
    key32 = hashlib.sha256(b"TEST-ONLY-THREEFISH").digest()
    tweak = struct.pack("<2Q", 0, 0)
    blk = bytes(range(32))
    check("mode1 Threefish-256 round-trip (tweak [block, 0])",
          threefish256_decrypt_block(key32, tweak, threefish256_encrypt_block(key32, tweak, blk)) == blk)
    k2 = mode2_key()
    iv = bytes(range(16))
    ct = aes_cbc_encrypt(k2, iv, b"test-user")
    check("mode2 PBKDF2-HMAC-SHA256(100k) + AES-256-CBC round-trip",
          aes_cbc_decrypt(k2, iv, ct) == b"test-user")
    check("mode2 envelope layout [IV 16 B][ciphertext]",
          len(iv + ct) == 16 + len(ct))
    try:
        mode0_decrypt("not-base64!!!")
        check("negative: invalid Base64 rejected", False)
    except Exception:
        check("negative: invalid Base64 rejected", True)
    try:
        bad = bytearray(base64.b64decode(b64))
        bad[-1] ^= 1
        mode0_decrypt(base64.b64encode(bytes(bad)).decode())
        check("negative: corrupted ciphertext rejected", False)
    except Exception:
        check("negative: corrupted ciphertext rejected", True)
    print("VERIFY OK")


if __name__ == "__main__":
    main()
