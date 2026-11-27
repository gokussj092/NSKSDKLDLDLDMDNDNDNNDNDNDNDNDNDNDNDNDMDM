"""Synthetic-only tests for the REESE 3.23.28 merge.

No network, no real user data. The fixture is the analyst's synthetic
sample (TEST-NET profile, HWID ABC-123, password test123).
"""
import importlib.util
import json
import unittest
from pathlib import Path

STAGE = Path(__file__).resolve().parents[4]
SCRIPT = STAGE / "decoders/Python/apps/REESE_TUNNEL/reese_tunnel.py"
FIXTURE = Path(__file__).resolve().parent / "fixtures/sample_synthetic.rt"
FRAGMENT = STAGE / "_fragments/groupC/engine.py.fragment"


def load():
    spec = importlib.util.spec_from_file_location("reese146", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Reese146Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load()
        cls.raw = FIXTURE.read_bytes()

    def test_sample_opens_via_decode(self):
        doc = self.mod.decode(self.raw, hwid="ABC-123", password="test123")
        self.assertEqual(doc["meta"]["name"], "Mi SSH")
        self.assertEqual(doc["config"]["sshHost"], "203.0.113.10")
        self.assertEqual(doc["config"]["profileName"], "Mi SSH")

    def test_sample_opens_via_decode_rt_file(self):
        meta, config = self.mod.decode_rt_file(
            str(FIXTURE), hwid="abc-123", password="test123")
        self.assertEqual(meta["name"], "Mi SSH")
        self.assertEqual(config["sshHost"], "203.0.113.10")

    def test_wrong_password_is_error_4(self):
        with self.assertRaises(self.mod.RSE5Error) as ctx:
            self.mod.decode(self.raw, hwid="ABC-123", password="wrong")
        self.assertEqual(ctx.exception.code, 4)

    def test_missing_credentials(self):
        with self.assertRaises(self.mod.RSE5Error) as ctx:
            self.mod.decode(self.raw, hwid="", password="")
        self.assertEqual(ctx.exception.code, 3)  # HWID checked first

    def test_bad_magic_is_error_1(self):
        with self.assertRaises(self.mod.RSE5Error) as ctx:
            self.mod.decode(b"garbage-bytes-here", hwid="", password="")
        self.assertEqual(ctx.exception.code, 1)
        self.assertIsNone(self.mod.run(b"garbage-bytes-here"))

    def test_truncated_legacy_header(self):
        with self.assertRaises(self.mod.RSE5Error):
            self.mod.decode(b"RSE1" + b"\x00" * 10, hwid="X", password="y")

    def test_text_parsers_synthetic(self):
        vless = self.mod.parse_text(
            "vless://11111111-2222-3333-4444-555555555555@example.com:443"
            "?type=ws&security=tls&path=%2Fws&host=h.example.com#My%20VLESS")
        self.assertEqual((vless["protocol"], vless["host"], vless["port"]),
                         ("VLESS", "example.com", 443))
        trojan = self.mod.parse_text(
            "trojan://secret@example.com:443?security=tls#T")
        self.assertEqual((trojan["protocol"], trojan["id"]),
                         ("TROJAN", "secret"))
        with self.assertRaises(self.mod.LinkError):
            self.mod.parse_text("")

    def test_reese_engine_fragment_exists(self):
        text = FRAGMENT.read_text(encoding="utf-8")
        self.assertIn('"reese"', text)
        self.assertIn("REESE_TUNNEL/reese_tunnel.py", text)


if __name__ == "__main__":
    unittest.main()
