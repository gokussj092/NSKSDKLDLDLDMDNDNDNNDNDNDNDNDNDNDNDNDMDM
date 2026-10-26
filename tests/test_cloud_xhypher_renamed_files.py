"""Xhypher text/file aliases through the real isolated Cloud worker.

Synthetic golden fixtures only. Never commit owner-provided config contents.
"""
from __future__ import annotations

import base64
import json
import unittest
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from cloud.workers.python.engine import (
    DecodeFailure, _xhypher_export_in_renamed_file, decode_file, decode_text
)
from tests.test_apna_vpn import profile_seal


ROOT = Path(__file__).resolve().parents[1]


class XhypherAliases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.golden = json.loads(
            (ROOT / "tests/golden/xhypher_tunnel_pro_vectors.json").read_text("utf-8")
        )
        cls.ciphertext = cls.golden["file"].encode("ascii")
        cls.expected = cls.golden["expectedFile"]

    def test_full_xhypher_text_variants_keep_complete_json(self):
        for scheme in ("xhyphertunnelpro://", "xhypher://"):
            with self.subTest(scheme=scheme):
                result = decode_text(scheme + self.ciphertext.decode("ascii"))
                self.assertEqual(result["status"], "success")
                self.assertEqual(result["kind"], "text")
                self.assertEqual(result["structuredJson"]["config"], self.expected)
                self.assertEqual(json.loads(result["rawText"]), result["structuredJson"])

    def test_renamed_vendor_carriers_route_by_verified_content(self):
        for suffix in ("hat", "bdnet"):
            for scheme in ("xhyphertunnelpro://", "xhypher://"):
                with self.subTest(suffix=suffix, scheme=scheme):
                    wire = (scheme.encode("ascii") + self.ciphertext)
                    self.assertTrue(_xhypher_export_in_renamed_file(suffix, wire))
                    result = decode_file(suffix, wire, full_hat=True)
                    self.assertEqual(result["format"], suffix)
                    self.assertEqual(result["decoder"]["name"], "RENZ / XHYPHER")
                    self.assertEqual(result["structuredJson"]["config"], self.expected)
                    self.assertEqual(json.loads(result["rawText"]), result["structuredJson"])
                    self.assertFalse(result["isPartial"])

        original = decode_file("xhypher", self.ciphertext)
        self.assertEqual(original["structuredJson"]["config"], self.expected)

    def test_short_links_and_malformed_carriers_are_never_reinterpreted(self):
        for source in (
            b"xhypher://abc123",
            b"xhyphertunnelpro://https://example.invalid/token",
            b"xhyphertunnelpro://%" + self.ciphertext,
            b"prefix xhyphertunnelpro://" + self.ciphertext,
            b"xhyphertunnelpro://" + b"A" * 80 + b"!",
        ):
            self.assertFalse(_xhypher_export_in_renamed_file("hat", source))
            self.assertFalse(_xhypher_export_in_renamed_file("bdnet", source))
        self.assertFalse(_xhypher_export_in_renamed_file("npvs",
                         b"xhyphertunnelpro://" + self.ciphertext))
        # A valid-looking carrier is not a successful decryption by itself.
        with self.assertRaises(DecodeFailure):
            decode_file("hat", b"xhyphertunnelpro://" + b"A" * 64, full_hat=True)

    def test_native_hat_and_bdnet_keep_their_original_engines(self):
        authentic_hat = {"profilev5": {"connection_mode": "plaintext-test"},
                         "metadata": {"name": "synthetic-hat"}}
        key = base64.b64decode("zbNkuNCGSLivpEuep3BcNA==")
        encrypted = AES.new(key, AES.MODE_ECB).encrypt(
            pad(json.dumps(authentic_hat).encode("utf-8"), 16)
        )
        hat = base64.b64encode(encrypted)
        self.assertFalse(_xhypher_export_in_renamed_file("hat", hat))
        hat_result = decode_file("hat", hat, full_hat=True)
        self.assertEqual(hat_result["structuredJson"], authentic_hat)
        self.assertNotEqual(hat_result["decoder"]["name"], "RENZ / XHYPHER")

        native_bdnet = {"friendly_name": "synthetic-bdnet", "port": 443}
        bdnet = profile_seal(json.dumps(native_bdnet).encode("utf-8"))
        self.assertFalse(_xhypher_export_in_renamed_file("bdnet", bdnet))
        bdnet_result = decode_file("bdnet", bdnet)
        self.assertEqual(bdnet_result["structuredJson"], native_bdnet)
        self.assertNotEqual(bdnet_result["decoder"]["name"], "RENZ / XHYPHER")


if __name__ == "__main__":
    unittest.main()
