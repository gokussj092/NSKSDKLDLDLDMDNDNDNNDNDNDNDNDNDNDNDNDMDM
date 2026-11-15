#!/usr/bin/env python3
"""ZIVPN Tunnel — synthetic round-trip verifier for this dossier.

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


import subprocess

PT = b'<?xml version="1.0"?><properties><entry key="tunnelType">4</entry></properties>'


def derive_key(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password, salt, 1000, 16)


def seal_envelope(pt, password=b"TEST-ONLY-SYNTHETIC-PASSWORD"):
    salt = bytes(range(32))
    nonce = bytes(range(12))
    key = derive_key(password, salt)
    ct, tag = aes_gcm_encrypt(key, nonce, pt)
    env = (base64.b64encode(salt).decode() + "." + base64.b64encode(nonce).decode()
           + "." + base64.b64encode(ct + tag).decode())
    return env


def open_envelope(env, password=b"TEST-ONLY-SYNTHETIC-PASSWORD"):
    parts = env.split(".")
    if len(parts) != 3:
        raise ValueError("bad .ziv envelope: expected 3 dot-separated parts")
    salt = base64.b64decode(parts[0])
    nonce = base64.b64decode(parts[1])
    blob = base64.b64decode(parts[2])
    if len(salt) != 32 or len(nonce) != 12:
        raise ValueError("bad salt/nonce length")
    key = derive_key(password, salt)
    return aes_gcm_decrypt(key, nonce, blob[:-16], blob[-16:])


def des_ecb_roundtrip(data):
    # OpenSSL 3.x keeps DES in the legacy provider; load it explicitly.
    key = b"TESTDES1"
    enc = subprocess.run(["openssl", "enc", "-des-ecb", "-K", key.hex(), "-nopad",
                          "-provider", "legacy", "-provider", "default"],
                         input=data, capture_output=True, check=True)
    dec = subprocess.run(["openssl", "enc", "-des-ecb", "-d", "-K", key.hex(), "-nopad",
                          "-provider", "legacy", "-provider", "default"],
                         input=enc.stdout, capture_output=True, check=True)
    return dec.stdout == data


def main():
    env = seal_envelope(PT)
    check(".ziv envelope round-trip (PBKDF2-SHA256 1000 + AES-128-GCM)",
          open_envelope(env) == PT)
    check("DES-ECB round-trip via openssl oracle", des_ecb_roundtrip(bytes(range(16))))
    try:
        open_envelope(env.rsplit(".", 1)[0])
        check("negative: envelope with 2 parts rejected", False)
    except Exception:
        check("negative: envelope with 2 parts rejected", True)
    try:
        parts = env.split(".")
        blob = bytearray(base64.b64decode(parts[2]))
        blob[-1] ^= 1
        parts[2] = base64.b64encode(bytes(blob)).decode()
        open_envelope(".".join(parts))
        check("negative: tampered GCM tag rejected", False)
    except Exception:
        check("negative: tampered GCM tag rejected", True)
    try:
        open_envelope(env, password=b"wrong-password")
        check("negative: wrong password rejected", False)
    except Exception:
        check("negative: wrong password rejected", True)
    print("VERIFY OK")


if __name__ == "__main__":
    main()
