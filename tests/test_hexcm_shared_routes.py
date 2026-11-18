"""Shared .hexcm regression: legacy Hex Tunnel vs Hex Custom 10.6.7 HXS3.

Exercises the actual isolated Cloud worker, without accessing Firestore, using
synthetic exports only. Never stores private user configurations or passwords.
"""
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "decoders/Python/apps/Hex_Custom/Hex_Custom_10.6.7.py"
spec = importlib.util.spec_from_file_location("spdecode_hex_custom_1067", SOURCE)
decoder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(decoder)

from cloud.workers.python.engine import decode_file, DecodeFailure


class HexCustomTunnelRouting(unittest.TestCase):
    def test_new_unprotected_hxs3_uses_new_codec_and_complete_json(self):
        profile = {
            "version": 1,
            "server": {"host": "example.invalid", "port": 443},
            "meta": {"name": "Synthetic Hex Custom"},
        }
        blob = decoder.seal(profile, password=None)
        self.assertEqual(blob[:6], b"HXS3\x03\x00")
        actual = decode_file("hexcm", blob)
        self.assertEqual(actual["format"], "hexcm")
        self.assertEqual(actual["structuredJson"]["server"]["host"], "example.invalid")
        self.assertEqual(actual["structuredJson"]["meta"]["name"], "Synthetic Hex Custom")
        self.assertEqual(actual["isPartial"], False)

    def test_protected_hxs3_with_valid_and_wrong_password(self):
        profile = {"version": 1, "server": {"host": "example.invalid", "port": 80}}
        blob = decoder.seal(profile, password="synthetic-pass")
        self.assertEqual(blob[:6], b"HXS3" + bytes([3, 1]))
        ok = decode_file("hexcm", blob, credentials={"password": "synthetic-pass"})
        self.assertEqual(ok["structuredJson"]["server"]["host"], "example.invalid")
        self.assertFalse(ok["isPartial"])
        with self.assertRaises(DecodeFailure) as wrong:
            decode_file("hexcm", blob, credentials={"password": "wrong-password"})
        self.assertEqual(wrong.exception.code, "AUTH_FAILED")

    def test_protected_hxs3_without_password_requests_it_instead_of_generic_error(self):
        profile = {"version": 1, "server": {"host": "example.invalid"}}
        # No expensive Argon2 work required to prove the credential gate:
        # cryptographic authentication is performed only *after* the prompt.
        blob = bytearray(decoder.seal(profile))
        blob[5] = 1
        with self.assertRaises(DecodeFailure) as failure:
            decode_file("hexcm", bytes(blob))
        self.assertEqual(failure.exception.code, "PASSWORD_REQUIRED")

    def test_legacy_hex_tunnel_envelope_still_uses_original_reader(self):
        cases = json.loads((ROOT / "tests/golden/hexcm_vectors.json").read_text())["documents"]
        case = next(item for item in cases if not item.get("reject"))
        result = decode_file("hexcm", case["wire"].encode("ascii"))
        self.assertEqual(result["structuredJson"]["config"], case["expected"])
        self.assertFalse(result["isPartial"])

    def test_old_hex_tunnel_does_not_accept_hxs3_password(self):
        cases = json.loads((ROOT / "tests/golden/hexcm_vectors.json").read_text())["documents"]
        case = next(item for item in cases if not item.get("reject"))
        with self.assertRaises(DecodeFailure) as failure:
            decode_file("hexcm", case["wire"].encode("ascii"), credentials={"password": "x"})
        self.assertEqual(failure.exception.code, "CREDENTIALS_NOT_ALLOWED")


if __name__ == "__main__":
    unittest.main()
