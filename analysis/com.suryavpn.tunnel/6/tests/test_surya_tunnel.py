"""Tests del metodo Surya Tunnel 1.6 (build 6).

Vectores SINTETICOS con la etiqueta de prueba (SURYA_TEST_LABEL=1);
ningun secreto real, ningun servidor real, ninguna red. El fixture
synthetic_v3.st se genero con esa misma etiqueta de prueba.
"""
import base64
import json
import os
import sys
import unittest

os.environ["SURYA_TEST_LABEL"] = "1"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import surya_tunnel as surya

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name, binary=False):
    mode = "rb" if binary else "r"
    with open(os.path.join(FIXTURES, name), mode, encoding=None if binary else "utf-8") as fh:
        return fh.read()


class TestStFile(unittest.TestCase):
    def test_positive_real_layout_fixture_v3(self):
        expected = json.loads(load_fixture("synthetic_profile.json"))
        blob = load_fixture("synthetic_v3.st", binary=True)
        self.assertTrue(blob.startswith(b"SPN1\x03"))
        out = surya.decode_file(blob)
        self.assertEqual(out["profiles"][0]["host"], "example.test")
        self.assertEqual(out["profiles"][0]["port"], 22)
        self.assertEqual(out["profiles"][0]["lockMode"], "NONE")
        self.assertEqual(out["exportedAt"], expected["exportedAt"])

    def test_positive_v3_roundtrip(self):
        export = json.loads(load_fixture("synthetic_profile.json"))
        js = json.dumps(export).encode("utf-8")
        blob = surya.config_encrypt_raw_v3(js)
        self.assertEqual(surya.decode_file(blob), surya.parse_export(export))

    def test_positive_v2_v1_roundtrip(self):
        export = json.loads(load_fixture("synthetic_profile.json"))
        js = json.dumps(export).encode("utf-8")
        nonce = os.urandom(12)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        v2 = surya.MAGIC + b"\x02" + nonce + AESGCM(surya._key_v2()).encrypt(nonce, js, None)
        self.assertEqual(surya.decode_file(v2), surya.parse_export(export))

    def test_positive_spw1_password(self):
        export = json.loads(load_fixture("synthetic_profile.json"))
        js = json.dumps(export).encode("utf-8")
        blob = surya.config_encrypt_raw_v3(js)
        import hashlib
        salt, siv = os.urandom(16), os.urandom(12)
        key = hashlib.pbkdf2_hmac("sha256", b"secret", salt, 120000, 32)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        spw1 = surya.MAGIC_PW + salt + siv + AESGCM(key).encrypt(siv, blob, surya.MAGIC_PW)
        with self.assertRaises(surya.SuryaDecodeError) as ctx:
            surya.decode_file(spw1)
        self.assertEqual(ctx.exception.code, "PASSWORD_REQUIRED")
        self.assertEqual(surya.decode_file(spw1, "secret"), surya.parse_export(export))

    def test_negative_truncated(self):
        self.assertIsNone(surya.config_decrypt_raw(b"SPN1\x03short"))

    def test_negative_garbage(self):
        self.assertIsNone(surya.decode_file(b"\x00" * 64))


class TestTextShares(unittest.TestCase):
    def test_positive_svpn1(self):
        profile = {"host": "example.test", "port": 22, "modeIndex": 0}
        text = "SVPN1:" + base64.b64encode(json.dumps(profile).encode()).decode()
        out = surya.decode_text(text)
        self.assertEqual(out["profiles"][0]["host"], "example.test")

    def test_positive_svpn2(self):
        export = json.loads(load_fixture("synthetic_profile.json"))
        js = json.dumps(export).encode("utf-8")
        blob = surya.config_encrypt_raw_v3(js)
        text = "SVPN2:" + base64.b64encode(blob).decode()
        self.assertEqual(surya.decode_text(text), surya.parse_export(export))

    def test_positive_svpn4_roundtrip(self):
        export = json.loads(load_fixture("synthetic_profile.json"))
        js = json.dumps(export)
        out = surya.decode_text("SVPN4:" + surya._svpn34_encrypt(js))
        self.assertEqual(out, surya.parse_export(export))

    def test_negative_unknown_text(self):
        self.assertIsNone(surya.decode_text("hello world, not a share"))


if __name__ == "__main__":
    unittest.main()
