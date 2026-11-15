"""Tests del metodo WyrVPN (build 473).

Vectores SINTETICOS con claves de prueba generadas aqui mismo; no hay
credenciales reales, ni servidores reales, ni red. La criptografia usada
es la extraida a tools/crypto_pure.py (codigo generico, sin claves de
formato). El descifrado con parametros reales esta cubierto por el
--self-test del script operativo (ver RESULTS.md).
"""
import base64
import hashlib
import hmac as hmac_mod
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
sys.path.insert(0, os.path.dirname(__file__))

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
TEST_PASSWORD = b"TEST-ONLY-SYNTHETIC-PASSWORD-2026-11-15"
TEST_KEY_16 = b"TEST-ONLY-KEY-16"
TEST_KEY_32 = b"TEST-ONLY-SYNTHETIC-KEY-32-BYTES"

from crypto_pure import v01_decrypt, v01_encrypt, DecodeError


def load_fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return json.load(fh)


class TestV01Envelope(unittest.TestCase):
    def test_positive_roundtrip(self):
        doc = load_fixture("synthetic_catalog.json")
        blob = v01_encrypt(json.dumps(doc).encode(), TEST_KEY_16)
        self.assertTrue(blob.startswith("djAx"))
        out = json.loads(v01_decrypt(blob, TEST_KEY_16))
        self.assertEqual(out, doc)

    def test_positive_empty_plaintext(self):
        blob = v01_encrypt(b"", TEST_KEY_16)
        self.assertEqual(v01_decrypt(blob, TEST_KEY_16), b"")

    def test_negative_tampered_tag(self):
        blob = v01_encrypt(b'{"Version": "9.9-sintetico"}', TEST_KEY_16)
        raw = bytearray(base64.b64decode(blob))
        raw[-1] ^= 0x01
        with self.assertRaises(DecodeError):
            v01_decrypt(base64.b64encode(bytes(raw)).decode(), TEST_KEY_16)

    def test_negative_wrong_key(self):
        blob = v01_encrypt(b"hola", TEST_KEY_16)
        with self.assertRaises(DecodeError):
            v01_decrypt(blob, b"WRONG-TEST-KEY-16")

    def test_negative_truncated(self):
        blob = v01_encrypt(b"hola mundo sintetico", TEST_KEY_16)
        with self.assertRaises(DecodeError):
            v01_decrypt(blob[:20], TEST_KEY_16)

    def test_negative_bad_magic(self):
        raw = b"v02" + os.urandom(12) + os.urandom(16)
        with self.assertRaises(DecodeError):
            v01_decrypt(base64.b64encode(raw).decode(), TEST_KEY_16)

    def test_negative_invalid_base64(self):
        with self.assertRaises(DecodeError):
            v01_decrypt("!!!no-es-base64!!!", TEST_KEY_16)

    def test_fixture_schema(self):
        doc = load_fixture("synthetic_catalog.json")
        self.assertIn("Version", doc)
        self.assertIn("Servers", doc)
        self.assertIsInstance(doc["Servers"], list)
        self.assertEqual(doc["Servers"][0]["ServerIPHost"], "203.0.113.10")


if __name__ == "__main__":
    unittest.main()
