"""Tests del metodo Peru VPN 4.1.2 (build 412).

Vectores SINTETICOS con claves de prueba (PERU_TEST_KEYS=1); ningun
secreto real, ningun servidor real, ninguna red. El sobre del catalogo
y los campos se verifican contra los fixtures generados con esas mismas
claves de prueba (ver tests/fixtures/).
"""
import base64
import json
import os
import sys
import unittest

os.environ["PERU_TEST_KEYS"] = "1"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import codec

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name):
    with open(os.path.join(FIXTURES, name), "rb") as fh:
        return fh.read()


class TestPeruCatalog(unittest.TestCase):
    def test_positive_fixture_decodes(self):
        blob = load_fixture("synthetic_catalog.b64")
        doc = codec.decode_catalog(blob)
        expected = json.loads(load_fixture("synthetic_catalog.json"))
        self.assertEqual(doc["Version"], expected["Version"])
        self.assertEqual(len(doc["Servers"]), 1)
        srv = doc["Servers"][0]
        self.assertEqual(srv["Name"], "Test Server")
        self.assertEqual(srv["ServerIP"], "203.0.113.10")
        self.assertEqual(srv["ServerUser"], "testuser")
        self.assertEqual(srv["ServerPass"], "testpass")
        self.assertEqual(srv["Payload"], "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        self.assertEqual(srv["SNI"], "example.com")

    def test_positive_envelope_roundtrip(self):
        # Round-trip at the envelope layer only (the fixture above covers
        # full field decode; the field codec has no public encoder).
        plain = json.dumps({"Version": "999", "Servers": [{"Name": "R"}]})
        salt_hex = "0123456789abcdef" * 2
        text = salt_hex + plain
        key = codec._catalog_key()
        raw = bytes(b ^ key[i % 32] for i, b in enumerate(text.encode()))
        blob = base64.b64encode(raw)
        self.assertEqual(codec.decrypt_catalog(blob), plain)

    def test_positive_empty_field(self):
        self.assertEqual(codec.decode_field(""), "")

    def test_negative_truncated_envelope(self):
        with self.assertRaises(codec.DecodeError):
            codec.decode_catalog(base64.b64encode(b"corto"))

    def test_negative_garbage(self):
        with self.assertRaises(codec.DecodeError):
            codec.decode_catalog(base64.b64encode(b"\x00" * 200))

    def test_negative_bad_field(self):
        # decode_field does not wrap the base64 error (unlike the full
        # catalog path, which maps everything to DecodeError).
        with self.assertRaises(Exception):
            codec.decode_field("!!!not-base64!!!")

    def test_fixture_has_no_real_ips(self):
        import re
        raw = load_fixture("synthetic_catalog.json").decode()
        self.assertNotRegex(raw, r"\b(?!203\.0\.113\.)(?:\d{1,3}\.){3}\d{1,3}\b")


if __name__ == "__main__":
    unittest.main()
