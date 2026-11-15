#!/usr/bin/env python3
"""Synthetic-only verifier/test support for this dossier.

All keys are TEST-ONLY constants (bytes(range(...))). No real format keys,
no real credentials, no download endpoints, no network access.
"""
"""Tests for the PPH GOOD VPN method (synthetic vectors only, no network, no secrets).

Run from the dossier directory:
    python3 tests/test_method.py
    python3 -m unittest discover -s tests -v
    python3 -m pytest tests/test_method.py -v   (if pytest is installed)
"""
import base64
import hashlib
import hmac
import json
import struct
import sys
import unittest
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"

import hashlib, hmac as hmac_mod, struct

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



DELTA = 0x2E0BA747  # XXTEA delta used by the catalog (c_01.decryptMain)
TEST_KEY = bytes(range(16))  # TEST-ONLY

def catalog_encrypt(plain, key=TEST_KEY):
    return base64.b64encode(xxtea_encrypt(plain, key, DELTA)).decode()

def catalog_decrypt(text, key=TEST_KEY):
    """One Base64 line -> XXTEA (length word) -> JSON bytes. Raises ValueError on bad base64 / bad length word."""
    try:
        raw = base64.b64decode(text, validate=True)
    except Exception as exc:
        raise ValueError("bad base64") from exc
    return xxtea_decrypt(raw, key, DELTA)

def parser_encode(data):
    """c_01$Parser.encode: Base64 with -18 per byte."""
    return base64.b64encode(bytes((b - 18) & 0xFF for b in data)).decode()

def parser_decode(text):
    """c_01$Parser.decode: Base64 with +18 per byte."""
    raw = base64.b64decode(text, validate=True)
    return bytes((b + 18) & 0xFF for b in raw)

class TestPphMethod(unittest.TestCase):
    def setUp(self):
        self.fx = json.loads((FIXTURE_DIR / "pph_fixture.json").read_text())

    def test_fixture_catalog_decrypts(self):
        pt = catalog_decrypt(self.fx["catalog_b64"])
        self.assertEqual(json.loads(pt), self.fx["plaintext"])

    def test_roundtrip_fresh(self):
        msg = json.dumps({"Version": "9.9-test", "Servers": []}).encode()
        self.assertEqual(catalog_decrypt(catalog_encrypt(msg)), msg)

    def test_truncated_rejected(self):
        with self.assertRaises(ValueError):
            catalog_decrypt(self.fx["catalog_b64"][:-4])

    def test_bad_base64_rejected(self):
        with self.assertRaises(ValueError):
            catalog_decrypt("!!!not-base64!!!")

    def test_html_rejected(self):
        with self.assertRaises(ValueError):
            catalog_decrypt(base64.b64encode(b"<html>not a catalog</html>").decode())

    def test_parser_roundtrip(self):
        data = b"test-payload-content-123"
        self.assertEqual(parser_decode(parser_encode(data)), data)

    def test_parser_encoded_differs_from_raw(self):
        data = b"test-payload-content-123"
        self.assertNotEqual(parser_encode(data), base64.b64encode(data).decode())

if __name__ == "__main__":
    unittest.main(verbosity=2)
