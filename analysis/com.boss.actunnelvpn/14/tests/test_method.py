#!/usr/bin/env python3
"""Tests for the Ac Tunnel VPN method dossier (com.boss.actunnelvpn / 14).

unittest (stdlib). Offline, synthetic vectors only, no secrets.
Run from this dossier directory:
    python3 -m unittest tests.test_method -v
(`pytest` is not installed in this VM; the same file also runs under
pytest where it is available.)
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DOSSIER = os.path.dirname(HERE)
FIXTURES = os.path.join(HERE, "fixtures")
sys.path.insert(0, os.path.join(DOSSIER, "tools"))

import crypto_pure as cp  # noqa: E402
import verify as v  # noqa: E402


class TestMethod(unittest.TestCase):
    def test_aes128_fips197(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.assertEqual(cp.aes_encrypt_block(key, pt).hex(),
                         "69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(cp.aes_decrypt_block(key, bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")), pt)

    def test_aes256_fips197(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.assertEqual(cp.aes_encrypt_block(key, pt).hex(),
                         "8ea2b7ca516745bfeafc49904b496089")

    def test_verify_script(self):
        # tools/verify.py runs its positive + negative synthetic checks.
        try:
            v.main()
        except SystemExit as e:
            self.fail("tools/verify.py failed (exit %s)" % e.code)

    def test_fixtures_are_synthetic(self):
        for name in sorted(os.listdir(FIXTURES)):
            with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn("TEST", text, name)
            self.assertNotIn("password", text.lower().replace("testpassword", ""), name)

    def test_xxtea_delta_roundtrip(self):
        msg = b'{"Version": "9.9-test", "Servers": []}'
        self.assertEqual(v.xxtea_decrypt(v.xxtea_encrypt(msg, v.TEST_KEY16, v.DELTA), v.TEST_KEY16, v.DELTA), msg)

    def test_mode2_pbkdf2_key_length(self):
        self.assertEqual(len(v.mode2_key()), 32)

if __name__ == "__main__":
    unittest.main()
