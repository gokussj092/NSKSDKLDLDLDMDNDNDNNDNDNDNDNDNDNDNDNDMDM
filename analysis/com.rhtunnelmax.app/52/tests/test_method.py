"""Tests del metodo RH Tunnel Lite (build 52).

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

from crypto_pure import (
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    bytes_to_chinese,
    chinese_to_bytes,
    c01_decrypt,
    c01_encrypt,
    _pkcs7_unpad,
    sab_decrypt,
    sab_encrypt,
    xxtea_decrypt,
    xxtea_encrypt,
)

TEST_KEY_TEXT = "TEST-ONLY-SYNTHETIC-KEY"
PREFIX = "Telegram@noob_xman"


def load_fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return json.load(fh)


class TestSabBlob(unittest.TestCase):
    def _doc_bytes(self):
        doc = load_fixture("synthetic_catalog.json")
        return (PREFIX + json.dumps(doc)).encode()

    def test_positive_sab_roundtrip(self):
        data = self._doc_bytes()
        blob = sab_encrypt(data, TEST_KEY_TEXT)
        self.assertEqual(sab_decrypt(blob, TEST_KEY_TEXT), data)

    def test_positive_xxtea_roundtrip(self):
        plain = b'{"ServerIPHost": "203.0.113.10", "Version": "9.9"}'
        ct = xxtea_encrypt(plain, TEST_KEY_TEXT)
        self.assertEqual(xxtea_decrypt(ct, TEST_KEY_TEXT), plain)

    def test_positive_c01_link_roundtrip(self):
        text = '{"Name": "Servidor sintetico", "ServerIPHost": "203.0.113.10"}'
        enc = c01_encrypt(text, TEST_KEY_TEXT)
        self.assertEqual(c01_decrypt(enc, TEST_KEY_TEXT), text)

    def test_positive_chinese_packing_roundtrip(self):
        data = bytes(range(256)) * 2
        self.assertEqual(chinese_to_bytes(bytes_to_chinese(data)), data)

    def test_positive_aes_cbc_roundtrip(self):
        key = hashlib.sha256(TEST_KEY_TEXT.encode()).digest()
        plain = b"0123456789abcdef" * 3
        ct = aes_cbc_encrypt(key, plain)
        self.assertEqual(_pkcs7_unpad(aes_cbc_decrypt(key, ct)), plain)

    def test_negative_sab_wrong_key(self):
        blob = sab_encrypt(self._doc_bytes(), TEST_KEY_TEXT)
        with self.assertRaises(Exception):
            sab_decrypt(blob, "WRONG-TEST-KEY")

    def test_negative_xxtea_truncated(self):
        ct = xxtea_encrypt(b"12345678", TEST_KEY_TEXT)
        self.assertIsNone(xxtea_decrypt(ct[:4], TEST_KEY_TEXT))

    def test_negative_c01_invalid_base64(self):
        with self.assertRaises(Exception):
            c01_decrypt("!!!no-es-base64!!!", TEST_KEY_TEXT)

    def test_negative_sab_short_blob(self):
        # Un blob de 8 B no es multiplo de 16: el AES-CBC lo rechaza.
        blob = bytes_to_chinese(b"12345678")
        with self.assertRaises(Exception):
            sab_decrypt(blob, TEST_KEY_TEXT)

    def test_fixture_schema(self):
        doc = load_fixture("synthetic_catalog.json")
        self.assertIn("Version", doc)
        self.assertIn("Servers", doc)
        self.assertEqual(doc["Servers"][0]["ServerIPHost"], "203.0.113.10")


if __name__ == "__main__":
    unittest.main()
