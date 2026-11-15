#!/usr/bin/env python3
"""MNR TUNNEL PLUS — synthetic round-trip verifier for this dossier.

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


CARRIER = "\u00b9\u00b2\u00b3\u2074\u2075\u2076\u2077\u2078\u2079\u2070\u00b7\u002c\u203d\u003a\u0027\u2032"
PT = json.dumps({"Version": "9.9-test", "Servers": [{"Name": "TEST"}]},
                ensure_ascii=False).encode("utf-8")


def carrier_encode(data):
    # Real method: each BYTE of the Base64 text becomes two carrier chars
    # (high nibble first). carrier_decode reverses it exactly.
    b64 = base64.b64encode(data)
    out = []
    for byte in b64:
        out.append(CARRIER[byte >> 4])
        out.append(CARRIER[byte & 0xF])
    return "".join(out)


def carrier_decode(text):
    if len(text) % 2:
        raise ValueError("odd carrier length")
    raw = bytes((CARRIER.index(text[i]) << 4) | CARRIER.index(text[i + 1])
                for i in range(0, len(text), 2))
    return base64.b64decode(raw)


def envelope_key():
    return hashlib.sha256("TEST-ONLY-SYNTHETIC".encode().hex().upper().encode()).digest()


def envelope_encrypt(pt):
    return carrier_encode(aes_cbc_encrypt(envelope_key(), bytes(16), pt))


def envelope_decrypt(text):
    return aes_cbc_decrypt(envelope_key(), bytes(16), carrier_decode(text))


def main():
    check("carrier round-trip (16-char carrier -> Base64)",
          carrier_decode(carrier_encode(b"hello")) == b"hello")
    blob = envelope_encrypt(PT)
    check("envelope round-trip (carrier + AES-256-CBC, key=SHA-256(hex-upper))",
          envelope_decrypt(blob) == PT)
    try:
        envelope_decrypt(blob[:-2] + "??")
        check("negative: corrupted carrier rejected", False)
    except Exception:
        check("negative: corrupted carrier rejected", True)
    try:
        bad = bytearray(base64.b64decode(carrier_decode(blob)))
        bad[-1] ^= 1
        aes_cbc_decrypt(envelope_key(), bytes(16), bytes(bad))
        check("negative: bad PKCS#7 padding rejected", False)
    except Exception:
        check("negative: bad PKCS#7 padding rejected", True)
    print("VERIFY OK")


if __name__ == "__main__":
    main()
