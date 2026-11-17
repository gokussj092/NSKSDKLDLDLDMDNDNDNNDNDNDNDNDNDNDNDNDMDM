"""Tests del metodo DeepTune-VPN (build 8).

Vectores SINTETICOS con claves de prueba generadas aqui mismo; no hay
credenciales reales, ni servidores reales, ni red. La criptografia
usada es el sobre generico de tools/envelope.py (misma construccion,
parametros REDUCIDOS solo para el test). El descifrado con parametros
reales esta cubierto por la re-corrida en vivo y el asset empaquetado
(ver RESULTS.md).
"""
import base64
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from envelope import aes_gcm_decrypt, decrypt_blob, encrypt_blob

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
TEST_PASSWORD = b"TEST-ONLY-PASSWORD-00"
TEST_PARAMS = {"time_cost": 1, "memory_kib": 8, "parallelism": 1}


class TestEnvelope(unittest.TestCase):
    def test_roundtrip_with_test_password(self):
        plain = b'{"Version": "9.9.9-TEST", "Servers": []}'
        blob = encrypt_blob(plain, TEST_PASSWORD, **TEST_PARAMS)
        self.assertEqual(decrypt_blob(blob, TEST_PASSWORD, **TEST_PARAMS), plain)

    def test_salt_sensitive(self):
        plain = b"hello"
        b1 = encrypt_blob(plain, TEST_PASSWORD, salt=bytes(16), nonce=bytes(12), **TEST_PARAMS)
        b2 = encrypt_blob(plain, TEST_PASSWORD, salt=bytes([1]) + bytes(15), nonce=bytes(12), **TEST_PARAMS)
        self.assertNotEqual(b1, b2)
        self.assertEqual(decrypt_blob(b1, TEST_PASSWORD, **TEST_PARAMS), plain)

    def test_wrong_password_fails(self):
        blob = encrypt_blob(b"secret", TEST_PASSWORD, **TEST_PARAMS)
        with self.assertRaises(Exception):
            decrypt_blob(blob, b"TEST-ONLY-WRONG-000", **TEST_PARAMS)

    def test_tampered_tag_fails(self):
        blob = encrypt_blob(b"secret", TEST_PASSWORD, **TEST_PARAMS)
        raw = bytearray(base64.b64decode(blob))
        raw[-1] ^= 0x01
        with self.assertRaises(Exception):
            aes_gcm_decrypt(bytes(raw), TEST_PASSWORD, **TEST_PARAMS)

    def test_layout_salt_nonce_ciphertext(self):
        blob = encrypt_blob(b"x" * 10, TEST_PASSWORD, salt=bytes(range(16)),
                            nonce=bytes(range(12)), **TEST_PARAMS)
        raw = base64.b64decode(blob)
        self.assertEqual(raw[:16], bytes(range(16)))
        self.assertEqual(raw[16:28], bytes(range(12)))
        self.assertGreaterEqual(len(raw), 44)

    def test_fixture_shape(self):
        with open(os.path.join(FIXTURES, "synthetic_catalog.json"), encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["Version"], "9.9.9-TEST")
        self.assertEqual(len(data["Servers"]), 1)
        self.assertEqual(len(data["Networks"]), 1)
        self.assertEqual(data["Servers"][0]["ServerHost"], "203.0.113.20")


if __name__ == "__main__":
    unittest.main()
