#!/usr/bin/env python3
"""Dossier tests for STR VIP Proxy 1.42.5 (no network, no secrets).

Loads the staged operational catalog script by path and decodes the
synthetic fixture (TEST-NET values only, sealed with the script's own
encrypt_token). A synthetic fixture proves the implemented logic, not
compatibility with a real release; live compatibility is proven by the
byte-for-byte live re-run documented in RESULTS.md.
"""
import importlib.util
import json
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOSSIER = HERE.parent
STAGING = DOSSIER.parents[2]
SCRIPT = (STAGING / "decoders/Python/apps/STR_VIP_Proxy/STR_VIP_Proxy.py")


def load_script(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestSyntheticCatalog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_script(SCRIPT, "str_vip_proxy_dossier")

    def test_fixture_round_trip(self):
        raw = (HERE / "fixtures/synthetic_catalog.json").read_bytes()
        doc = self.mod.decode(raw)
        self.assertEqual(doc["meta"]["serverVersion"], "9.9.9-test")
        self.assertEqual(len(doc["servers"]), 1)
        self.assertEqual(doc["servers"][0]["host"], "198.51.100.1")
        self.assertEqual(doc["tweaks"][0]["payload"], "test-payload")
        self.assertNotIn("enc:", json.dumps(doc))

    def test_run_returns_json_text(self):
        raw = (HERE / "fixtures/synthetic_catalog.json").read_bytes()
        out = self.mod.run(raw)
        self.assertIsInstance(out, str)
        self.assertEqual(json.loads(out)["servers"][0]["host"],
                         "198.51.100.1")

    def test_run_invalid_returns_none(self):
        self.assertIsNone(self.mod.run(b"not json"))
        self.assertIsNone(self.mod.run(b""))

    def test_tampered_token_rejected(self):
        doc = json.loads((HERE / "fixtures/synthetic_catalog.json")
                         .read_text())
        token = doc["servers"][0]["host"]
        bad = token[:-2] + ("AA" if token[-2:] != "AA" else "BB")
        doc["servers"][0]["host"] = bad
        with self.assertRaises(Exception):
            self.mod.decode(json.dumps(doc))


if __name__ == "__main__":
    unittest.main()
