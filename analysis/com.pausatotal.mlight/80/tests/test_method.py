"""Tests del metodo M Light (build 80).

Vectores SINTETICOS con claves de prueba generadas aqui mismo; no hay
credenciales reales, ni servidores reales, ni red. La criptografia
usada es el codec baybayin de tools/baybayin.py (codigo generico, sin
claves de formato) + AES de pycryptodome con una clave de prueba. El
descifrado con parametros reales esta cubierto por el --self-test del
script operativo (ver RESULTS.md).
"""
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from baybayin import ALPHABET, baybayin_decode, baybayin_encode

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
TEST_PASSWORD = b"TEST-ONLY-PASSWORD-00"


def derive_key_test(password):
    """Misma derivacion que el metodo real, con clave de prueba."""
    return hashlib.sha256(password.hex().upper().encode("ascii")).digest()


def aes_cbc_test(key, iv, data, decrypt=False):
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(data) if decrypt else cipher.encrypt(data)


def pad(data):
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


def unpad(data):
    n = data[-1]
    if n < 1 or n > 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("padding invalido")
    return data[:-n]


def encrypt_config_test(plaintext, password=TEST_PASSWORD):
    import base64
    key = derive_key_test(password)
    ct = aes_cbc_test(key, b"\x00" * 16, pad(plaintext.encode("utf-8")))
    return baybayin_encode(base64.b64encode(ct))


def decrypt_config_test(text, password=TEST_PASSWORD):
    import base64
    raw = baybayin_decode(text)
    ct = base64.b64decode(raw.decode("utf-8"))
    key = derive_key_test(password)
    return unpad(aes_cbc_test(key, b"\x00" * 16, ct, decrypt=True)).decode("utf-8")


class TestBaybayinCodec(unittest.TestCase):
    def test_roundtrip_bytes(self):
        data = bytes(range(256))
        self.assertEqual(baybayin_decode(baybayin_encode(data)), data)

    def test_alphabet_size(self):
        self.assertEqual(len(ALPHABET), 17)
        self.assertEqual(len(set(ALPHABET)), 17)

    def test_odd_length_rejected(self):
        with self.assertRaises(ValueError):
            baybayin_decode(ALPHABET[0])

    def test_unknown_char_rejected(self):
        with self.assertRaises(ValueError):
            baybayin_decode("ZZ")


class TestConfigEnvelope(unittest.TestCase):
    def test_roundtrip_with_test_password(self):
        sample = json.dumps({"Version": "9.9.9-TEST", "Servers": []})
        self.assertEqual(decrypt_config_test(encrypt_config_test(sample)), sample)

    def test_wrong_password_fails(self):
        enc = encrypt_config_test('{"Version": "9.9.9-TEST"}')
        with self.assertRaises(Exception):
            decrypt_config_test(enc, password=b"TEST-ONLY-WRONG-000")

    def test_fixture_shape(self):
        with open(os.path.join(FIXTURES, "synthetic_catalog.json"), encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["Version"], "9.9.9-TEST")
        self.assertEqual(len(data["Servers"]), 1)
        self.assertEqual(data["Servers"][0]["ServerIP"], "203.0.113.10")
        self.assertNotIn("203.0.113.10".replace("203", "999"), json.dumps(data))


if __name__ == "__main__":
    unittest.main()
