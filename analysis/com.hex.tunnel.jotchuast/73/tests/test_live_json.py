"""Validates the stored HexVPN live probe (no network, no secrets)."""
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIVE = ROOT / "live.json"


class LiveJsonTests(unittest.TestCase):
    def test_no_catalog_and_27_denied_probes(self):
        live = json.loads(LIVE.read_text())
        self.assertEqual(live["catalog"]["status"], "NO_CATALOG")
        self.assertEqual(live["servers"], [])
        self.assertEqual(live["networks"], [])
        self.assertEqual(live["payloads"], [])
        self.assertIsNone(live["catalog_version"])
        self.assertEqual(len(live["probes"]), 27)
        self.assertTrue(all(p["http_status"] == 401 for p in live["probes"]))
        self.assertEqual(
            [p["node"] for p in live["probes"]][:5],
            ["(root)", "servers", "free_servers", "vip_servers", "free"],
        )

    def test_no_download_apis_or_secrets(self):
        text = json.dumps(json.loads(LIVE.read_text()))
        self.assertNotIn("api_key", text)
        self.assertNotIn("AIza", text)
        self.assertNotIn("download_url", text)
        self.assertNotIn("token", text.lower())


if __name__ == "__main__":
    unittest.main()
