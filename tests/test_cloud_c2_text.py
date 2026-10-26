"""Synthetic Phase G text parity with canonical decoders, no Telegram handlers.

Only report supported cases as parity-confirmed. HAPP encrypted private-key
variants remain intentionally unsupported without user-provisioned keys.
"""
from __future__ import annotations

import json
import unittest

from cloud.workers.python.engine import decode_text, DecodeFailure
from cloud.workers.python.text_bridge import dispatch
from scripts.android_g_text_fixtures import build
from tests.golden.a23_generators import dark_bytes

class CloudC2TextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = build()["vectors"]

    def test_phase_g_synthetic_reference_vectors(self):
        self.assertGreaterEqual(len(self.cases), 55)
        misses = []
        for case in self.cases:
            with self.subTest(scheme=case["scheme"]):
                actual = dispatch(case["input"])
                if not actual:
                    misses.append(case["scheme"])
                    continue
                try:
                    parsed = json.loads(actual) if isinstance(actual, str) else actual
                except ValueError:
                    misses.append(case["scheme"])
                    continue
                if parsed != case["expected"]:
                    misses.append(case["scheme"])
        self.assertEqual(misses, [], "Source-derived text parity gaps: " + ", ".join(misses))

    def test_dark_tunnel_real_name_and_historical_text_prefixes(self):
        # The independent A23 fixture is a full AES-CFB/MessagePack envelope.
        # The four aliases must select one decoder, not four crypto methods.
        payload = dark_bytes().decode("ascii")
        expected = decode_text("dt://" + payload)
        self.assertEqual(expected["kind"], "text")
        self.assertFalse(expected["isPartial"])
        self.assertIn("synthetic", expected["rawText"])
        for prefix in ("dark://", "darktunnel://", "dtunnel://", "dt://"):
            with self.subTest(prefix=prefix):
                actual = decode_text(prefix + payload)
                self.assertEqual(actual["rawText"], expected["rawText"])
                self.assertEqual(actual["structuredJson"], expected["structuredJson"])
                self.assertEqual(dispatch(prefix + payload), expected["rawText"])
        with self.assertRaises(DecodeFailure):
            decode_text("darktunnel://not-valid-dark-config")

    def test_text_bridge_is_protected_against_unknown_and_private_key_formats(self):
        self.assertIsNone(dispatch("happ://crypt/AAAA"))
        self.assertIsNone(dispatch("https://untrusted.example.invalid/download"))
        self.assertIsNone(dispatch("no known protocol"))
        with self.assertRaises(DecodeFailure):
            decode_text("unsupported text only")

    def test_worker_returns_full_structured_json_for_source_vector(self):
        case = next(row for row in self.cases if row["scheme"] == "falcontunnel://import/")
        result = decode_text(case["input"])
        self.assertEqual(result["structuredJson"], case["expected"])
        self.assertFalse(result["isPartial"])
        self.assertEqual(result["kind"], "text")

if __name__ == "__main__":
    unittest.main()
