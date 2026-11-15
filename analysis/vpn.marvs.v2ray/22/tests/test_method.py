"""Tests del metodo RH Tunnel Secure (Marvs V2Ray) (build 22).

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

from crypto_pure import _aes_gcm_decrypt, _aes_gcm_encrypt, _argon2id, _encrypt_blob


def load_fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return json.load(fh)


def open_envelope_test(blob_b64: str, password: bytes):
    """Abre un sobre Base64(salt[16] || nonce[12] || ct || tag) con la
    contrasena de prueba y parametros REDUCIDOS (solo para el test)."""
    raw = base64.b64decode(blob_b64)
    if len(raw) < 44:
        raise ValueError("sobre demasiado corto")
    salt, nonce, rest = raw[:16], raw[16:28], raw[28:]
    key = _argon2id(password, salt, time_cost=1, memory_kib=8,
                    parallelism=1, tag_len=32)
    return _aes_gcm_decrypt(key, nonce, rest[:-16], rest[-16:], aad=salt)


class TestArgon2Envelope(unittest.TestCase):
    def test_positive_argon2id_deterministic(self):
        salt = bytes(range(16))
        k1 = _argon2id(TEST_PASSWORD, salt, time_cost=1, memory_kib=8,
                       parallelism=1, tag_len=32)
        k2 = _argon2id(TEST_PASSWORD, salt, time_cost=1, memory_kib=8,
                       parallelism=1, tag_len=32)
        self.assertEqual(k1, k2)
        self.assertEqual(len(k1), 32)

    def test_positive_argon2id_salt_sensitive(self):
        k1 = _argon2id(TEST_PASSWORD, bytes(16), time_cost=1, memory_kib=8,
                       parallelism=1, tag_len=32)
        k2 = _argon2id(TEST_PASSWORD, bytes([1]) + bytes(15), time_cost=1,
                       memory_kib=8, parallelism=1, tag_len=32)
        self.assertNotEqual(k1, k2)

    def test_positive_envelope_roundtrip_small_params(self):
        doc = load_fixture("synthetic_catalog.json")
        plain = json.dumps(doc).encode()
        salt, nonce = os.urandom(16), os.urandom(12)
        key = _argon2id(TEST_PASSWORD, salt, time_cost=1, memory_kib=8,
                        parallelism=1, tag_len=32)
        ct, tag = _aes_gcm_encrypt(key, nonce, plain, aad=salt)
        blob = base64.b64encode(salt + nonce + ct + tag).decode()
        self.assertEqual(open_envelope_test(blob, TEST_PASSWORD), plain)

    def test_positive_encrypt_blob_layout(self):
        """_encrypt_blob produce el layout salt||nonce||ct||tag en Base64."""
        blob = _encrypt_blob(b'{"Version": "9.9-sintetico"}', TEST_PASSWORD,
                             os.urandom(16), os.urandom(12))
        raw = base64.b64decode(blob)
        self.assertGreaterEqual(len(raw), 44)

    def test_negative_tampered_tag(self):
        salt, nonce = os.urandom(16), os.urandom(12)
        key = _argon2id(TEST_PASSWORD, salt, time_cost=1, memory_kib=8,
                        parallelism=1, tag_len=32)
        ct, tag = _aes_gcm_encrypt(key, nonce, b"secreto-sintetico", aad=salt)
        bad_tag = bytes([tag[0] ^ 1]) + tag[1:]
        with self.assertRaises(ValueError):
            _aes_gcm_decrypt(key, nonce, ct, bad_tag, aad=salt)

    def test_negative_wrong_password(self):
        doc = load_fixture("synthetic_catalog.json")
        plain = json.dumps(doc).encode()
        salt, nonce = os.urandom(16), os.urandom(12)
        key = _argon2id(TEST_PASSWORD, salt, time_cost=1, memory_kib=8,
                        parallelism=1, tag_len=32)
        ct, tag = _aes_gcm_encrypt(key, nonce, plain, aad=salt)
        blob = base64.b64encode(salt + nonce + ct + tag).decode()
        with self.assertRaises(ValueError):
            open_envelope_test(blob, b"WRONG-TEST-PASSWORD")

    def test_negative_truncated_envelope(self):
        with self.assertRaises(ValueError):
            open_envelope_test(base64.b64encode(b"corto").decode(), TEST_PASSWORD)

    def test_negative_html_instead_of_envelope(self):
        with self.assertRaises(Exception):
            open_envelope_test(base64.b64encode(
                b"<html><head><title>Error</title></head></html>").decode(),
                TEST_PASSWORD)

    def test_fixture_schema(self):
        doc = load_fixture("synthetic_catalog.json")
        self.assertIn("Version", doc)
        self.assertEqual(doc["Servers"][0]["ServerIPHost"], "203.0.113.10")


if __name__ == "__main__":
    unittest.main()
