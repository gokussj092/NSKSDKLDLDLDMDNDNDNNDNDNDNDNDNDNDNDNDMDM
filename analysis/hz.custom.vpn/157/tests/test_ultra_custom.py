"""Tests del metodo Ultra Custom 15.7 (build 157).

Vectores SINTETICOS con claves de prueba (ULTRA_CUSTOM_TEST_KEYS=1);
ningun secreto real, ningun servidor real, ninguna red. El fixture
synthetic_test.ua se genero con esas mismas claves de prueba.
"""
import base64
import json
import os
import sys
import unittest
import zlib

os.environ["ULTRA_CUSTOM_TEST_KEYS"] = "1"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import ultra_custom as uc

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name, binary=False):
    mode = "rb" if binary else "r"
    with open(os.path.join(FIXTURES, name), mode,
              encoding=None if binary else "utf-8") as fh:
        return fh.read()


SAMPLE_XML = ('<?xml version="1.0" encoding="UTF-8"?>\n<properties>\n'
              '<entry key="file.profileName">Test</entry>\n'
              '<entry key="sshServer">example.com</entry>\n</properties>\n').encode("utf-8")


class TestUaf2(unittest.TestCase):
    def test_positive_fixture(self):
        text = load_fixture("synthetic_test.ua").strip()
        self.assertTrue(text.startswith("!UAF2=:"))
        out = uc.decode(text)
        self.assertEqual(out["properties"]["file.profileName"], "Test Profile")
        self.assertEqual(out["properties"]["file.appVersionCode"], "157")
        self.assertEqual(out["properties"]["sshServer"], "example.com")

    def test_positive_roundtrip(self):
        out = uc.decode(uc.uaf2_encode(SAMPLE_XML))
        self.assertEqual(out["properties"]["file.profileName"], "Test")
        self.assertEqual(out["properties"]["sshServer"], "example.com")

    def test_negative_tampered(self):
        text = uc.uaf2_encode(SAMPLE_XML)
        body = text[len("!UAF2=:"):]
        raw = bytearray(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        raw[-1] ^= 1
        bad = "!UAF2=:" + base64.urlsafe_b64encode(bytes(raw)).decode().rstrip("=")
        with self.assertRaises(uc.DecodeError) as ctx:
            uc.decode(bad)
        self.assertEqual(ctx.exception.code, "AUTH_FAILED")


class TestLegacyAndUap1(unittest.TestCase):
    def test_positive_legacy_roundtrip(self):
        inflater = zlib.compressobj(9, zlib.DEFLATED, -15, zdict=uc.LINK_DICTIONARY)
        blob = b"EXA1" + inflater.compress(SAMPLE_XML) + inflater.flush()
        text = base64.urlsafe_b64encode(uc.mask(blob)).decode().rstrip("=")
        self.assertEqual(uc.decode(text)["properties"]["file.profileName"], "Test")
        self.assertEqual(uc.decode("ua://" + text)["properties"]["file.profileName"], "Test")

    def test_positive_uap1_roundtrip(self):
        import hashlib
        import secrets
        from Crypto.Cipher import AES
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        key = hashlib.pbkdf2_hmac("sha256", b"pw123", salt, 210000, 32)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        header = b"UAP1" + salt + nonce
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(SAMPLE_XML)
        blob = header + ciphertext + tag
        out = uc.decode(uc.uaf2_encode(blob), password="pw123")
        self.assertEqual(out["properties"]["file.profileName"], "Test")
        with self.assertRaises(uc.DecodeError) as ctx:
            uc.decode(uc.uaf2_encode(blob))
        self.assertEqual(ctx.exception.code, "PASSWORD_REQUIRED")


class TestUcs(unittest.TestCase):
    def test_positive_synthetic_signed_subscription(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes, serialization
        private = ec.generate_private_key(ec.SECP256R1())
        public_der = private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        inner = {"id": "12345678-1234-4234-8234-123456789abc", "title": "Test sub",
                 "note": "", "update_url": "https://example.invalid/sub.ucs",
                 "status": "active", "revision": 3, "refresh_minutes": 60,
                 "expires_at": 0, "block_root": False, "mobile_only": False,
                 "login_hwid": False, "hwids": [],
                 "servers": [{"id": "srv1", "name": "Test",
                              "profile_payload": uc.uaf2_encode(SAMPLE_XML)}]}
        payload = json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode()
        signature = private.sign(uc.UCS_DOMAIN + payload, ec.ECDSA(hashes.SHA256()))
        outer = {"format": "CSS1", "payload": base64.b64encode(payload).decode(),
                 "public_key": base64.b64encode(public_der).decode(),
                 "signature": base64.b64encode(signature).decode()}
        doc = uc.decode_ucs(json.dumps(outer).encode())
        self.assertEqual(doc["title"], "Test sub")
        self.assertEqual(doc["revision"], 3)
        self.assertEqual(doc["servers"][0]["profile"]["properties"]["file.profileName"], "Test")
        tampered = dict(outer)
        tampered["payload"] = base64.b64encode(payload[:-1] + b" ").decode()
        with self.assertRaises(uc.DecodeError) as ctx:
            uc.decode_ucs(json.dumps(tampered).encode())
        self.assertEqual(ctx.exception.code, "INVALID_UCS")


if __name__ == "__main__":
    unittest.main()
