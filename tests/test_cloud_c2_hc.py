"""C2 authenticated HTTP Custom HCCFG regression using existing synthetic vectors."""
from __future__ import annotations

import json
import unittest

from cloud.workers.python.engine import DecodeFailure, decode_file
from tests.golden.hc_sip_new_variants import (
    S4_SYNTHETIC_PASSWORD, SYNTHETIC_HWID,
    hccfg_file, hccfg_hwid_file,
)

class CloudC2HcTests(unittest.TestCase):
    def test_password_protected_hccfg(self):
        encrypted = hccfg_file(password=S4_SYNTHETIC_PASSWORD)
        with self.assertRaises(DecodeFailure) as caught:
            decode_file("hc", encrypted)
        self.assertEqual(caught.exception.code, "PASSWORD_REQUIRED")
        result = decode_file("hc", encrypted, credentials={"password": S4_SYNTHETIC_PASSWORD})
        self.assertEqual(result["structuredJson"]["config"][0]["host"], "example.org")
        self.assertFalse(result["isPartial"])

    def test_hwid_protected_hccfg(self):
        encrypted = hccfg_hwid_file()
        with self.assertRaises(DecodeFailure) as caught:
            decode_file("hc", encrypted)
        self.assertIn(caught.exception.code, ("HWID_REQUIRED", "HWID_PASSWORD_REQUIRED"))
        result = decode_file("hc", encrypted, credentials={"hwid": SYNTHETIC_HWID})
        self.assertEqual(result["structuredJson"]["config"][0]["host"], "example.org")

    def test_dual_locked_hccfg_authentication(self):
        encrypted = hccfg_hwid_file(password=S4_SYNTHETIC_PASSWORD)
        with self.assertRaises(DecodeFailure):
            decode_file("hc", encrypted)
        result = decode_file("hc", encrypted, credentials={
            "password": S4_SYNTHETIC_PASSWORD,
            "hwid": SYNTHETIC_HWID,
        })
        self.assertEqual(result["structuredJson"]["config"][0]["host"], "example.org")
        for invalid in (
            {"password": "incorrect", "hwid": SYNTHETIC_HWID},
            {"password": S4_SYNTHETIC_PASSWORD, "hwid": "B" * 32},
        ):
            with self.subTest(invalid_field=list(invalid)), self.assertRaises(DecodeFailure):
                decode_file("hc", encrypted, credentials=invalid)

    def test_credentials_are_never_generic_fallback(self):
        with self.assertRaises(DecodeFailure) as caught:
            decode_file("tls", b"invalid", credentials={"password": "wrong"})
        self.assertEqual(caught.exception.code, "CREDENTIALS_NOT_ALLOWED")

if __name__ == "__main__":
    unittest.main()
