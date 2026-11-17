#!/usr/bin/env python3
"""Dossier tests for Click Tunnel 1.0 (no network, no secrets).

Loads the staged operational catalog script by path and decodes the
bundled-asset fixture (a byte copy of the APK's own res/raw/noobdev.js:
catalog v1.0.0, 1 server, 1 tweak, all string fields still encrypted).
Also pins the catalog-rule behaviour: decode() returns the document
WITH DefUpdateURL/updater, and removing those two keys yields the
clean result document (the supplied bridge must do that stripping).
"""
import importlib.util
import json
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOSSIER = HERE.parent
STAGING = DOSSIER.parents[2]
SCRIPT = STAGING / "decoders/Python/apps/Click_Tunnel/Click_Tunnel.py"


def load_script(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestBundledCatalog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_script(SCRIPT, "click_tunnel_dossier")

    def test_bundled_fixture_decodes(self):
        raw = (HERE / "fixtures/bundled_catalog.js").read_bytes()
        doc = self.mod.decode(raw)
        self.assertEqual(doc["Version"], "1.0.0")
        self.assertEqual(len(doc["Servers"]), 1)
        self.assertEqual(len(doc["Tweaks"]), 1)

    def test_decode_keeps_download_keys(self):
        # Pinned behaviour (see ANALYSIS.md section 2): decode() returns
        # the document WITH the download endpoints; only main() strips
        # them when saving/printing. The supplied bridge must strip them.
        raw = (HERE / "fixtures/bundled_catalog.js").read_bytes()
        doc = self.mod.decode(raw)
        self.assertIn("DefUpdateURL", doc)
        self.assertIn("updater", doc)
        clean = {k: v for k, v in doc.items()
                 if k not in ("DefUpdateURL", "updater")}
        self.assertNotIn("DefUpdateURL", clean)
        self.assertNotIn("updater", clean)
        self.assertEqual(len(clean["Servers"]), 1)

    def test_run_returns_json_text(self):
        raw = (HERE / "fixtures/bundled_catalog.js").read_bytes()
        out = self.mod.run(raw)
        self.assertIsInstance(out, str)
        self.assertEqual(json.loads(out)["Version"], "1.0.0")

    def test_run_invalid_returns_none(self):
        self.assertIsNone(self.mod.run(b"not base64!!!"))
        self.assertIsNone(self.mod.run(b""))


if __name__ == "__main__":
    unittest.main()
