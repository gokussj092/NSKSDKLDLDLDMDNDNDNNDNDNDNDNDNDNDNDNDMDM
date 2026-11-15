#!/usr/bin/env python3
"""CHN TUNNEL LITE — synthetic round-trip verifier for this dossier.

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


DELTA = 0x85A92C1F
PT = json.dumps({"Version": "9.9-test", "Name": "TEST NETWORK",
                 "SNI": "www.example.org"}, ensure_ascii=False).encode("utf-8")


def mode0_encrypt(pt):
    inner = xxtea_encrypt(pt, TEST_KEY16, DELTA)
    return base64.b64encode(aes_cbc_encrypt(TEST_KEY16, TEST_IV, inner)).decode()


def mode0_decrypt(b64):
    inner = aes_cbc_decrypt(TEST_KEY16, TEST_IV, base64.b64decode(b64))
    return xxtea_decrypt(inner, TEST_KEY16, DELTA)


def carrier_decode(text):
    # NOTE: synthetic carrier only. The real mode-2 layer also swaps
    # adjacent bits after the XOR 0x5A step; that swap is NOT replicated
    # here — this test proves the invisible-character transport round-trips,
    # not the exact app transform (that is the operational script's job).
    bits = []
    for ch in text:
        if ch == "\u200b":
            bits.append(0)
        elif ch == "\u200c":
            bits.append(1)
        elif ch == "\u200d":
            continue
        else:
            raise ValueError("unexpected carrier char")
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        out.append(byte ^ 0x5A)
    return bytes(out)


def carrier_encode(data):
    chars = []
    for byte in data:
        byte ^= 0x5A
        for shift in (7, 6, 5, 4, 3, 2, 1, 0):
            chars.append("\u200c" if (byte >> shift) & 1 else "\u200b")
    return "".join(chars)


def main():
    b64 = mode0_encrypt(PT)
    check("mode0 round-trip (AES-128-CBC + XXTEA delta 0x85A92C1F)", mode0_decrypt(b64) == PT)
    key32 = hashlib.sha256(b"TEST-ONLY-THREEFISH").digest()
    tweak = struct.pack("<2Q", 0, 0)
    blk = bytes(range(32))
    check("mode1 Threefish-256 round-trip",
          threefish256_decrypt_block(key32, tweak, threefish256_encrypt_block(key32, tweak, blk)) == blk)
    check("mode2 invisible-carrier round-trip", carrier_decode(carrier_encode(b"test-user")) == b"test-user")
    try:
        mode0_decrypt(b64[:20])
        check("negative: truncated Base64 rejected", False)
    except Exception:
        check("negative: truncated Base64 rejected", True)
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
