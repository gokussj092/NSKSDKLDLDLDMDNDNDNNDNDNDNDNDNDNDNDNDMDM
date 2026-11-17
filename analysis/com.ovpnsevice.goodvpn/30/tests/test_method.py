"""Tests del metodo GOOD VPN (build 30).

Vectores SINTETICOS con claves de prueba generadas aqui mismo; no hay
credenciales reales, ni servidores reales, ni red. La criptografia usada
es la extraida a tools/xxtea_pure.py (codigo generico, sin claves de
formato). El descifrado con parametros reales esta cubierto por el
--url --summary del script operativo y el --self-test del script de
archivos (ver RESULTS.md).
"""
import base64
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
sys.path.insert(0, os.path.dirname(__file__))

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

TEST_KEY = b"TEST-ONLY-KEY-16"
TEST_DELTA = 0x2E0BA747

from xxtea_pure import xxtea_decrypt, xxtea_encrypt


def load_fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return json.load(fh)


def b64_inner_encode(value: str) -> str:
    """Android Base64.DEFAULT style: standard alphabet, newlines every 76 chars."""
    raw = base64.b64encode(value.encode("utf-8")).decode("ascii")
    return "\n".join(raw[i:i + 76] for i in range(0, len(raw), 76)) + "\n"


def b64_inner_decode(value: str):
    compact = "".join(value.split())
    try:
        raw = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
        return raw.decode("utf-8")
    except (ValueError, UnicodeError):
        return None


class TestXxteaRoundTrip(unittest.TestCase):
    def test_positive_round_trip(self):
        plain = b'{"Version":"0.0-test","Servers":[],"Networks":[]}'
        blob = xxtea_encrypt(plain, TEST_KEY, TEST_DELTA)
        self.assertEqual(xxtea_decrypt(blob, TEST_KEY, TEST_DELTA), plain)

    def test_positive_round_trip_unicode(self):
        plain = "Servidor — ünïcode ✓".encode("utf-8")
        blob = xxtea_encrypt(plain, TEST_KEY, TEST_DELTA)
        self.assertEqual(xxtea_decrypt(blob, TEST_KEY, TEST_DELTA), plain)

    def test_positive_empty(self):
        self.assertEqual(xxtea_decrypt(b"", TEST_KEY, TEST_DELTA), b"")

    def test_negative_wrong_key(self):
        plain = b'{"Version":"0.0-test"}'
        blob = xxtea_encrypt(plain, TEST_KEY, TEST_DELTA)
        result = xxtea_decrypt(blob, b"WRONG-TEST-KEY!", TEST_DELTA)
        self.assertTrue(result is None or result != plain)

    def test_negative_truncated(self):
        plain = b'{"Version":"0.0-test"}'
        blob = xxtea_encrypt(plain, TEST_KEY, TEST_DELTA)
        result = xxtea_decrypt(blob[:-4], TEST_KEY, TEST_DELTA)
        self.assertTrue(result is None or result != plain)

    def test_negative_tampered(self):
        plain = b'{"Version":"0.0-test"}'
        blob = bytearray(xxtea_encrypt(plain, TEST_KEY, TEST_DELTA))
        blob[0] ^= 0xFF
        result = xxtea_decrypt(bytes(blob), TEST_KEY, TEST_DELTA)
        self.assertTrue(result is None or result != plain)


class TestInnerBase64(unittest.TestCase):
    def test_positive_inner_round_trip(self):
        for value in ("203.0.113.10", "testuser", "GET / HTTP/1.1\r\nHost: example.org\r\n\r\n"):
            self.assertEqual(b64_inner_decode(b64_inner_encode(value)), value)

    def test_positive_inner_ignores_newlines(self):
        encoded = b64_inner_encode("203.0.113.10")
        self.assertIn("\n", encoded)
        self.assertEqual(b64_inner_decode(encoded.replace("\n", "")), "203.0.113.10")

    def test_negative_inner_invalid(self):
        self.assertIsNone(b64_inner_decode("!!!not-base64!!!"))

    def test_negative_inner_non_utf8(self):
        self.assertIsNone(b64_inner_decode(base64.b64encode(b"\xff\xfe\x00\x01").decode("ascii")))


class TestFixtureSchema(unittest.TestCase):
    def test_fixture_structure(self):
        doc = load_fixture("synthetic_catalog.json")
        self.assertEqual(doc["Version"], "0.0-test")
        self.assertIsInstance(doc["Servers"], list)
        self.assertIsInstance(doc["Networks"], list)
        self.assertEqual(len(doc["Servers"]), 2)
        self.assertEqual(len(doc["Networks"]), 2)
        for server in doc["Servers"]:
            for field in ("ServerName", "ServerIP", "Username", "Password"):
                self.assertIn(field, server)

    def test_fixture_has_no_real_hosts(self):
        doc = load_fixture("synthetic_catalog.json")
        text = json.dumps(doc)
        self.assertNotIn("ohmvpn", text)
        self.assertNotIn("raw.githubusercontent", text)
        for server in doc["Servers"]:
            self.assertTrue(server["ServerIP"].startswith("203.0.113."))

    def test_fixture_envelope_round_trip(self):
        doc = load_fixture("synthetic_catalog.json")
        plain = json.dumps(doc, ensure_ascii=False).encode("utf-8")
        blob = xxtea_encrypt(plain, TEST_KEY, TEST_DELTA)
        encoded = base64.b64encode(blob).decode("ascii")
        decoded = xxtea_decrypt(base64.b64decode(encoded), TEST_KEY, TEST_DELTA)
        self.assertEqual(json.loads(decoded.decode("utf-8")), doc)


if __name__ == "__main__":
    unittest.main()
