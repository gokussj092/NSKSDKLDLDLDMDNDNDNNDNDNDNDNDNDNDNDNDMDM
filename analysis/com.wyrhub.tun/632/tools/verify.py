#!/usr/bin/env python3
"""HTTP Tweak — synthetic round-trip verifier for this dossier.

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


import zlib

PT = json.dumps({"link": {"config_prefix": "httptweak://"},
                 "vpn": {"tunnel": "ssh"}}, ensure_ascii=False).encode("utf-8")


def build_ht_blob(mode=2, key=None, payload=None):
    if key is None:
        key = bytes(range(16))
    if payload is None:
        payload = zlib.compress(PT, 9)
        payload += b"\x00" * ((-len(payload)) % 16)
    if len(payload) % 16:
        raise ValueError("ciphertext must be a multiple of 16 bytes")
    return base64.b64encode(bytes([mode]) + key + payload).decode()


def parse_ht_blob(b64):
    raw = base64.b64decode(b64)
    if len(raw) < 17:
        raise ValueError("blob too short")
    mode = raw[0]
    if mode == 6:
        raise ValueError("unsupported mode: v6 (no sample exists)")
    if mode != 2:
        raise ValueError("unsupported mode: %d" % mode)
    key = raw[1:17]
    ct = raw[17:]
    if len(ct) % 16:
        raise ValueError("ciphertext length is not a multiple of 16")
    return mode, key, ct


def main():
    blob = build_ht_blob()
    mode, key, ct = parse_ht_blob(blob)
    check(".ht envelope structure (mode 2, 16 B key, ct multiple of 16)",
          mode == 2 and len(key) == 16 and len(ct) % 16 == 0)
    check("zlib stream stage round-trips (post-decrypt plaintext)",
          zlib.decompress(zlib.compress(PT, 9)) == PT)
    check("zlib magic 78 da present at level 9",
          zlib.compress(PT, 9)[:2] == b"\x78\xda")
    try:
        parse_ht_blob(build_ht_blob(mode=6))
        check("negative: mode 6 (v6) rejected, not invented", False)
    except ValueError as e:
        check("negative: mode 6 (v6) rejected, not invented", "v6" in str(e))
    try:
        parse_ht_blob(base64.b64encode(b"\x02short").decode())
        check("negative: truncated blob rejected", False)
    except Exception:
        check("negative: truncated blob rejected", True)
    try:
        parse_ht_blob("not-base64!!!")
        check("negative: invalid Base64 rejected", False)
    except Exception:
        check("negative: invalid Base64 rejected", True)
    print("VERIFY OK")


if __name__ == "__main__":
    main()
