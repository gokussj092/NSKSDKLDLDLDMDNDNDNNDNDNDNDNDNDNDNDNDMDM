"""Tests del metodo MO VPN (build 6).

Vectores SINTETICOS con claves de prueba generadas aqui mismo; no hay
credenciales reales, ni servidores reales, ni red. La criptografia usada
es la extraida a tools/xxtea_pure.py (codigo generico, sin claves de
formato). El descifrado con parametros reales esta cubierto por el
--self-test del script operativo (ver RESULTS.md).
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
TEST_PASS = "5741"

from xxtea_pure import xxtea_decrypt, xxtea_encrypt


def load_fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return json.load(fh)


def carrier_shift_encode(value: str, password: str) -> str:
    """Mirror of the app's De2 decrypt applied twice, in reverse."""
    shift = 2 * int(password)
    return "".join(chr(ord(ch) + shift) for ch in value)


def carrier_shift_decode(value: str, password: str) -> str:
    shift = 2 * int(password)
    return "".join(chr(ord(ch) - shift) for ch in value)


class TestXxteaRoundTrip(unittest.TestCase):
    def test_positive_round_trip(self):
        plain = b'{"FileName":"synthetic-test","Servers":[]}'
        blob = xxtea_encrypt(plain, TEST_KEY, TEST_DELTA)
        self.assertEqual(xxtea_decrypt(blob, TEST_KEY, TEST_DELTA), plain)

    def test_positive_round_trip_unicode(self):
        plain = "Servidor — ünïcode ✓".encode("utf-8")
        blob = xxtea_encrypt(plain, TEST_KEY, TEST_DELTA)
        self.assertEqual(xxtea_decrypt(blob, TEST_KEY, TEST_DELTA), plain)

    def test_positive_empty(self):
        self.assertEqual(xxtea_decrypt(b"", TEST_KEY, TEST_DELTA), b"")

    def test_negative_wrong_key(self):
        plain = b'{"FileName":"synthetic-test"}'
        blob = xxtea_encrypt(plain, TEST_KEY, TEST_DELTA)
        result = xxtea_decrypt(blob, b"WRONG-TEST-KEY!", TEST_DELTA)
        self.assertTrue(result is None or result != plain)

    def test_negative_truncated(self):
        plain = b'{"FileName":"synthetic-test"}'
        blob = xxtea_encrypt(plain, TEST_KEY, TEST_DELTA)
        result = xxtea_decrypt(blob[:-4], TEST_KEY, TEST_DELTA)
        self.assertTrue(result is None or result != plain)

    def test_negative_tampered(self):
        plain = b'{"FileName":"synthetic-test"}'
        blob = bytearray(xxtea_encrypt(plain, TEST_KEY, TEST_DELTA))
        blob[0] ^= 0xFF
        result = xxtea_decrypt(bytes(blob), TEST_KEY, TEST_DELTA)
        self.assertTrue(result is None or result != plain)


class TestFieldCarrierShift(unittest.TestCase):
    def test_positive_shift_round_trip(self):
        value = "203.0.113.10"
        self.assertEqual(
            carrier_shift_decode(carrier_shift_encode(value, TEST_PASS), TEST_PASS),
            value)

    def test_positive_shift_payload(self):
        value = "GET / HTTP/1.1\r\nHost: example.org\r\n\r\n"
        self.assertEqual(
            carrier_shift_decode(carrier_shift_encode(value, TEST_PASS), TEST_PASS),
            value)

    def test_negative_wrong_password(self):
        value = "203.0.113.10"
        encoded = carrier_shift_encode(value, TEST_PASS)
        # Wrong by 1: stays in chr() range, decodes to different text.
        self.assertNotEqual(carrier_shift_decode(encoded, "5742"), value)


class TestFixtureSchema(unittest.TestCase):
    def test_fixture_structure(self):
        doc = load_fixture("synthetic_catalog.json")
        self.assertEqual(doc["FileName"], "synthetic-test")
        self.assertIsInstance(doc["Servers"], list)
        self.assertIsInstance(doc["HTTPNetworks"], list)
        self.assertIsInstance(doc["SSLNetworks"], list)
        self.assertEqual(len(doc["Servers"]), 2)
        self.assertEqual(len(doc["HTTPNetworks"]), 2)
        for server in doc["Servers"]:
            for field in ("Name", "Category", "ServerIP", "V2ray"):
                self.assertIn(field, server)

    def test_fixture_has_no_real_hosts(self):
        doc = load_fixture("synthetic_catalog.json")
        text = json.dumps(doc)
        self.assertNotIn("mvpn5g.com", text)
        self.assertNotIn("tokenKey", text)
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
