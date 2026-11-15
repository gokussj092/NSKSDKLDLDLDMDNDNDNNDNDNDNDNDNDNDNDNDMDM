"""Tests del metodo MT KING NET (build 25).

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

from crypto_pure import _aes_gcm_decrypt, _aes_gcm_encrypt


def load_fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return json.load(fh)


def enc_wrap(plaintext: str, key: bytes) -> str:
    """Sobre enc: base64url(nonce[12] || ct || tag[16]), sin AAD."""
    nonce = os.urandom(12)
    ct, tag = _aes_gcm_encrypt(key, nonce, plaintext.encode(), aad=b"")
    return base64.urlsafe_b64encode(nonce + ct + tag).decode().rstrip("=")


def enc_unwrap(value: str, key: bytes) -> str:
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if len(raw) < 12 + 16:
        raise ValueError("sobre enc: demasiado corto")
    nonce, rest = raw[:12], raw[12:]
    return _aes_gcm_decrypt(key, nonce, rest[:-16], rest[-16:], aad=b"").decode()


class TestEncEnvelope(unittest.TestCase):
    def test_positive_roundtrip(self):
        for plain in ("203.0.113.10", "usuario-sintetico", '{"Version": "9.9"}'):
            self.assertEqual(enc_unwrap(enc_wrap(plain, TEST_KEY_32), TEST_KEY_32), plain)

    def test_positive_fixture_values(self):
        doc = load_fixture("synthetic_catalog.json")
        for server in doc["Servers"]:
            host = server["ServerIPHost"]
            self.assertEqual(enc_unwrap(enc_wrap(host, TEST_KEY_32), TEST_KEY_32), host)

    def test_negative_tampered_tag(self):
        wrapped = enc_wrap("203.0.113.10", TEST_KEY_32)
        raw = bytearray(base64.urlsafe_b64decode(wrapped + "=" * (-len(wrapped) % 4)))
        raw[-1] ^= 0x01
        bad = base64.urlsafe_b64encode(bytes(raw)).decode().rstrip("=")
        with self.assertRaises(ValueError):
            enc_unwrap(bad, TEST_KEY_32)

    def test_negative_wrong_key(self):
        wrapped = enc_wrap("203.0.113.10", TEST_KEY_32)
        with self.assertRaises(ValueError):
            enc_unwrap(wrapped, b"WRONG-TEST-SYNTHETIC-KEY-32-BYTE")

    def test_negative_truncated(self):
        wrapped = enc_wrap("203.0.113.10", TEST_KEY_32)
        with self.assertRaises(ValueError):
            enc_unwrap(wrapped[:10], TEST_KEY_32)

    def test_negative_invalid_base64url(self):
        with self.assertRaises(Exception):
            enc_unwrap("!!!no-es-base64url!!!", TEST_KEY_32)

    def test_hmac_signature_shape(self):
        """La firma App-Proof es HMAC-SHA256(sintetica, 'ts:nonce:path'):
        determinista, distinta si cambia el mensaje, 64 hex."""
        key = b"TEST-ONLY-HMAC-KEY"
        msg = b"1700000000:0123456789abcdef0123456789abcdef:/api/app"
        sig1 = hmac_mod.new(key, msg, hashlib.sha256).hexdigest()
        sig2 = hmac_mod.new(key, msg, hashlib.sha256).hexdigest()
        self.assertEqual(sig1, sig2)
        self.assertEqual(len(sig1), 64)
        sig3 = hmac_mod.new(key, msg + b"x", hashlib.sha256).hexdigest()
        self.assertNotEqual(sig1, sig3)

    def test_fixture_schema(self):
        doc = load_fixture("synthetic_catalog.json")
        self.assertIn("Version", doc)
        self.assertEqual(doc["Servers"][0]["ServerIPHost"], "203.0.113.10")


if __name__ == "__main__":
    unittest.main()
