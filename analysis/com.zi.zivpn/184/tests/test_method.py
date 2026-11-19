#!/usr/bin/env python3
"""Tests for the ZIVPN Tunnel offline dossier (com.zi.zivpn / 184).

unittest (stdlib). Offline, synthetic vectors only, no secrets beyond the
app-embedded format constants already in tools/zivpn_reference.py.
Run from this dossier directory:
    python3 -m unittest tests.test_method -v
(`pytest` is not installed in this VM; the same file also runs under
pytest where it is available.)
"""
import hashlib
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DOSSIER = os.path.dirname(HERE)
FIXTURES = os.path.join(HERE, "fixtures")
sys.path.insert(0, os.path.join(DOSSIER, "tools"))

import zivpn_reference as ref  # noqa: E402
import verify as v  # noqa: E402


class TestMethod(unittest.TestCase):
    def test_verify_script(self):
        # tools/verify.py runs its positive + negative synthetic checks.
        self.assertEqual(v.main(), 0)

    def test_fixtures_are_synthetic(self):
        # Every expected-JSON fixture holds synthetic TEST values, except
        # the frozen golden vector, whose one vendor hostname comes from
        # the online reference (documented in tools/make_fixtures.py).
        for name in sorted(os.listdir(FIXTURES)):
            if not name.endswith(".expected.json"):
                continue
            with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
                data = json.load(fh)
            text = json.dumps(data)
            if name == "ziv-golden.expected.json":
                self.assertIn("udpsg1.zivpn.com", text)
                continue
            self.assertIn("test.example", text, name)
            self.assertNotIn("password", text.lower(), name)

    def test_fixture_hashes_match_results(self):
        results = os.path.join(DOSSIER, "RESULTS.md")
        with open(results, encoding="utf-8") as fh:
            recorded = fh.read()
        for name in sorted(os.listdir(FIXTURES)):
            with open(os.path.join(FIXTURES, name), "rb") as fh:
                digest = hashlib.sha256(fh.read()).hexdigest()
            self.assertIn(digest, recorded, name)

    def test_envelope_roundtrip_both_styles(self):
        props = dict(v.PROPS)
        for legacy in (True, False):
            sealed = ref.seal_ziv(props, ref.LF1_PASSWORDS[0], v.SALT, v.IV,
                                  legacy=legacy)
            back, _xml, info = ref.open_ziv(sealed)
            self.assertEqual(back, props)
            self.assertIs(info["des_layer"], legacy)

    def test_wrong_password_rejected(self):
        sealed = ref.seal_ziv(v.PROPS, "wrong-password-test", v.SALT, v.IV,
                              legacy=False)
        with self.assertRaises(ref.DecodeError):
            ref.open_ziv(sealed)

    def test_golden_vector_opens_with_des_layer(self):
        with open(os.path.join(FIXTURES, "ziv-golden.ziv"),
                  encoding="utf-8") as fh:
            props, _xml, info = ref.open_ziv(fh.read())
        self.assertTrue(info["des_layer"])
        self.assertEqual(props.get("tunnelType"), "4")
        self.assertEqual(props.get("udpserver"), "udpsg1.zivpn.com")

    def test_emoji_fixture_opens(self):
        # Real-app shape: emoji in file.msg written as surrogate-pair
        # numeric references (java.util.Properties style).
        with open(os.path.join(FIXTURES, "ziv-emoji.ziv"),
                  encoding="utf-8") as fh:
            props, _xml, info = ref.open_ziv(fh.read())
        with open(os.path.join(FIXTURES, "ziv-emoji.expected.json"),
                  encoding="utf-8") as fh:
            self.assertEqual(props, json.load(fh))
        self.assertFalse(info["des_layer"])

    def test_lone_surrogate_rejected(self):
        with open(os.path.join(FIXTURES, "ziv-lone-surrogate.ziv"),
                  encoding="utf-8") as fh:
            sealed = fh.read()
        with self.assertRaises(ref.DecodeError):
            ref.open_ziv(sealed)

    def test_zivpn_text_roundtrip(self):
        xml = ref.properties_xml(v.PROPS).decode("utf-8")
        token = ref.seal_zivpn_text(xml)
        self.assertTrue(token.startswith("zivpn://"))
        self.assertEqual(ref.decode_zivpn(token), xml)
        self.assertIsNone(ref.decode_zivpn("zivpn://!!"))


if __name__ == "__main__":
    unittest.main()
