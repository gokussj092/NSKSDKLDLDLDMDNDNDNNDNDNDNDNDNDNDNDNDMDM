"""Tests del metodo VLX Tunnel VPN v1.11.24.2 (build 19).

Vectores SINTETICOS con contrasenas de formato de prueba (variables de
entorno VLX_KEY_LIVE / VLX_KEY_FILE / VLX_KEY_FIELD); ningun secreto
real, ningun servidor real, ninguna red. La criptografia es la del
propio script (Argon2id + AES-256-GCM en Python puro, con via rapida
opcional). Los sobres de prueba usan parametros REDUCIDOS salvo el
round-trip completo, que usa los parametros reales del formato
(~15-20 s por apertura en stdlib puro).
"""
import base64
import json
import os
import sys
import unittest

os.environ.setdefault("VLX_KEY_LIVE", "TEST-ONLY-VLX-LIVE-PASSWORD")
os.environ.setdefault("VLX_KEY_FILE", "TEST-ONLY-VLX-LIVE-PASSWORD")
os.environ.setdefault("VLX_KEY_FIELD", "TEST-ONLY-VLX-FIELD-PASSWORD")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import VLX_Tunnel_VPN as cat
import VLX_Tunnel_VPN_archivos as files

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

TEST_LIVE = b"TEST-ONLY-VLX-LIVE-PASSWORD"
TEST_FIELD = b"TEST-ONLY-VLX-FIELD-PASSWORD"


def load_fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return json.load(fh)


def seal_small(plain, password, time_cost=1, memory_kib=8):
    """Sella un sobre con parametros reducidos (solo para tests)."""
    salt, nonce = os.urandom(16), os.urandom(12)
    key = cat._argon2id(password, salt, time_cost=time_cost,
                        memory_kib=memory_kib, parallelism=1, tag_len=32)
    ct, tag = cat._aes_gcm_encrypt(key, nonce, plain, aad=salt)
    return base64.b64encode(salt + nonce + ct + tag).decode()


def open_small(blob_b64, password, time_cost=1, memory_kib=8):
    raw = base64.b64decode(blob_b64)
    salt, nonce, rest = raw[:16], raw[16:28], raw[28:]
    key = cat._argon2id(password, salt, time_cost=time_cost,
                        memory_kib=memory_kib, parallelism=1, tag_len=32)
    return cat._aes_gcm_decrypt(key, nonce, rest[:-16], rest[-16:], aad=salt)


class TestEnvelopeLayout(unittest.TestCase):
    def test_positive_argon2id_deterministic(self):
        salt = bytes(range(16))
        k1 = cat._argon2id(TEST_LIVE, salt, time_cost=1, memory_kib=8,
                           parallelism=1, tag_len=32)
        k2 = cat._argon2id(TEST_LIVE, salt, time_cost=1, memory_kib=8,
                           parallelism=1, tag_len=32)
        self.assertEqual(k1, k2)
        self.assertEqual(len(k1), 32)

    def test_positive_envelope_roundtrip_small_params(self):
        doc = load_fixture("synthetic_catalog.json")
        plain = json.dumps(doc).encode()
        blob = seal_small(plain, TEST_LIVE)
        self.assertEqual(open_small(blob, TEST_LIVE), plain)

    def test_positive_full_params_roundtrip_catalog(self):
        """Un sobre con los parametros reales del formato abre."""
        doc = {"Version": "9.9-sintetico", "Servers": [{"Name": "Test"}],
               "Networks": [{"Name": "TestNet"}]}
        plain = json.dumps(doc).encode()
        blob = cat._encrypt_blob(plain, TEST_LIVE, os.urandom(16), os.urandom(12))
        out, key = cat.decode_with_key(blob)
        self.assertEqual(key, "II")
        self.assertEqual(out, doc)

    def test_positive_full_params_roundtrip_vlx_file(self):
        profile = {"Name": "Test", "TunnelType": "SSH",
                   "Payload": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                   "SNI": "example.com"}
        plain = json.dumps(profile).encode()
        blob = files._encrypt_blob(plain, TEST_LIVE, os.urandom(16), os.urandom(12))
        out, key = files.decode_with_key(blob)
        self.assertEqual(key, "II")
        self.assertEqual(out, profile)

    def test_positive_field_envelope_in_profile(self):
        inner = files._encrypt_blob(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                                    TEST_FIELD, os.urandom(16), os.urandom(12))
        profile = {"Name": "Test", "Payload": inner}
        out = files._decode_profile_fields(profile)
        self.assertEqual(out["Payload"], "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

    def test_negative_tampered_tag(self):
        blob = seal_small(b"secreto-sintetico", TEST_LIVE)
        raw = bytearray(base64.b64decode(blob))
        raw[-1] ^= 1
        with self.assertRaises(ValueError):
            open_small(base64.b64encode(bytes(raw)).decode(), TEST_LIVE)

    def test_negative_wrong_password(self):
        blob = seal_small(b"secreto-sintetico", TEST_LIVE)
        with self.assertRaises(ValueError):
            open_small(blob, b"WRONG-TEST-PASSWORD")

    def test_negative_truncated_envelope(self):
        with self.assertRaises(Exception):
            cat.decrypt_envelope(b"corto")

    def test_fixture_schema(self):
        doc = load_fixture("synthetic_catalog.json")
        self.assertIn("Version", doc)
        self.assertEqual(doc["Servers"][0]["ServerIPHost"], "203.0.113.10")


if __name__ == "__main__":
    unittest.main()
