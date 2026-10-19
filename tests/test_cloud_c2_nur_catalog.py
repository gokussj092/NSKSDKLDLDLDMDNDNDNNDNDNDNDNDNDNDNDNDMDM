"""C2 separate authenticated NUR catalog handling, no outbound fetches."""
from __future__ import annotations

import unittest

from cloud.workers.python.engine import DecodeFailure, decode_catalog
from tests.test_nur_tunnel_solid import CATALOG, SOLID

class CloudC2NurCatalogTests(unittest.TestCase):
    def test_authenticated_server_catalog_preserves_complete_json(self):
        result = decode_catalog(CATALOG.encode("ascii"))
        doc = result["structuredJson"]
        self.assertIsInstance(doc["Version"], str)
        self.assertIsInstance(doc["Servers"], list)
        self.assertIsInstance(doc["Networks"], list)
        self.assertFalse(result["isPartial"])
        self.assertEqual(result["kind"], "nur_catalog")
        self.assertIn('"Version"', result["rawText"])

    def test_solid_profile_is_not_a_server_catalog(self):
        with self.assertRaises(DecodeFailure) as caught:
            decode_catalog(SOLID.encode("ascii"))
        self.assertEqual(caught.exception.code, "DECODE_FAILED")

    def test_tampered_catalog_is_rejected(self):
        chars = list(CATALOG)
        chars[21] = "A" if chars[21] != "A" else "B"
        with self.assertRaises(DecodeFailure):
            decode_catalog("".join(chars).encode("ascii"))

if __name__ == "__main__":
    unittest.main()
