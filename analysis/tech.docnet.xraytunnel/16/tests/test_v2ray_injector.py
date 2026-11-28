"""Tests del metodo V2Ray Injector 1.4.2 (build 16).

Vectores SINTETICOS con una clave de catalogo de prueba
(V2RAY_INJECTOR_CATALOG_KEY = "ab" * 32, solo para tests); ningun
secreto real, ningun servidor real, ninguna red. Los fixtures .v2k se
generaron con esa misma clave de prueba.
"""
import json
import os
import sys
import unittest

os.environ["V2RAY_INJECTOR_CATALOG_KEY"] = "ab" * 32
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import v2ray_injector as v2k

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return fh.read()


class TestV2kFile(unittest.TestCase):
    def test_positive_plain_v2k(self):
        doc = v2k.parse_v2k(load_fixture("sample_plain.v2k"))
        self.assertEqual(doc["name"], "Test Profile")
        self.assertFalse(doc["encrypted"])
        self.assertIn("vless", doc["xray"])

    def test_positive_encrypted_v2k(self):
        doc = v2k.parse_v2k(load_fixture("sample_enc.v2k"))
        self.assertEqual(doc["name"], "Test Profile")
        self.assertTrue(doc["encrypted"])
        self.assertIn("vless", doc["xray"])
        self.assertEqual(doc["xray_json"]["outbounds"][0]["protocol"], "vless")

    def test_positive_envelope_roundtrip(self):
        text = '{"servers": [], "configs": []}'
        self.assertEqual(v2k.decrypt_envelope(v2k.encrypt_envelope(text)), text)

    def test_positive_serialize_roundtrip_plain(self):
        cfg = {"name": "R", "description": "", "createdAt": "", "version": 1,
               "xray": "{}", "meta": {}}
        self.assertEqual(v2k.parse_v2k(v2k.serialize_v2k(cfg))["name"], "R")

    def test_negative_bad_magic(self):
        with self.assertRaises(ValueError):
            v2k.parse_v2k("XXXX|00|{}")

    def test_negative_tampered_envelope(self):
        enc = v2k.encrypt_envelope('{"a": 1}')
        iv, ct = enc.split(".", 1)
        bad = iv + "." + ("A" if ct[0] != "A" else "B") + ct[1:]
        self.assertIsNone(v2k.decrypt_envelope_or_none(bad))


class TestLinksAndXray(unittest.TestCase):
    def test_positive_links(self):
        for line in load_fixture("synthetic_links.txt").splitlines():
            if not line.strip():
                continue
            doc = v2k.parse_link(line)
            self.assertIn("protocol", doc)
        vless = v2k.parse_link(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443"
            "?security=tls&type=ws&path=%2Fws#TestWs")
        self.assertEqual(vless["protocol"], "VLESS")
        self.assertEqual(vless["address"], "example.com")
        self.assertEqual(vless["transport"], "ws")
        ss = v2k.parse_link(
            "ss://YWVzLTI1Ni1nY206dGVzdHBhc3N3b3Jk@203.0.113.10:8388#TestSS")
        self.assertEqual(ss["protocol"], "SHADOWSOCKS")
        self.assertEqual(ss["address"], "203.0.113.10")

    def test_positive_xray_json(self):
        doc = v2k.import_xray_json(load_fixture("synthetic_xray.json"))
        outbounds = doc.get("outbounds") or doc.get("servers") or []
        self.assertTrue(outbounds)

    def test_negative_unsupported_link(self):
        with self.assertRaises(ValueError):
            v2k.parse_link("unknown://example.com:443")


if __name__ == "__main__":
    unittest.main()
