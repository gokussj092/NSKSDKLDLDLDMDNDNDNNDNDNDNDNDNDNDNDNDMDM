"""MinaProNet public servers: decode_public_servers() on synthetic data only.

No network, no real servers, no real credentials. The fixture is a synthetic
3-entry list (TEST-NET hosts, TEST-ONLY passwords). Run from the repo root:

    python3 analysis/vpn.minapronet.com.eg/88/tests/test_public_servers.py
"""
import importlib.util
import json
import unittest
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parents[4]
FIXTURE = HERE.parent / "fixtures" / "public_servers_fixture.json"


def load_module():
    path = ROOT / "decoders" / "Python" / "apps" / "MinaProNet" / "MinaProNet.py"
    spec = importlib.util.spec_from_file_location("_mina_public_servers", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PublicServersTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()
        self.raw = FIXTURE.read_bytes()
        self.entries = json.loads(self.raw.decode("utf-8"))

    def test_summary_counts_match_fixture(self):
        res = self.module.decode_public_servers(self.raw)
        self.assertEqual(res["entries"], 3)
        self.assertEqual(res["online"], 2)
        self.assertEqual(res["countries"], 2)
        self.assertEqual(res["protocols"], {"ss": 2, "trojan": 1})

    def test_servers_returned_verbatim_without_url_or_size(self):
        res = self.module.decode_public_servers(self.raw)
        self.assertEqual(res["servers"], self.entries)
        self.assertNotIn("url", res)
        self.assertNotIn("bytes", res)

    def test_accepts_text_input(self):
        res = self.module.decode_public_servers(self.raw.decode("utf-8"))
        self.assertEqual(res["entries"], 3)

    def test_rejects_non_json(self):
        with self.assertRaises(self.module.DecodeError) as ctx:
            self.module.decode_public_servers(b"not json {")
        self.assertEqual(ctx.exception.code, "BAD_JSON")

    def test_rejects_non_list_empty_and_html(self):
        for bad in (b"{}", b"[]", b"<html>nope</html>"):
            with self.assertRaises(self.module.DecodeError) as ctx:
                self.module.decode_public_servers(bad)
            self.assertEqual(ctx.exception.code, "BAD_JSON")


if __name__ == "__main__":
    unittest.main()
