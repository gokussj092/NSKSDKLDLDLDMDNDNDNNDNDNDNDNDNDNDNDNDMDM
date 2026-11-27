"""Synthetic-only tests for the TunnelDOOM 4.3.5 re-analysis.

No network, no real catalog, no real credentials. The envelope and field
vectors are built here from the codec's own (fixed, build-level) keys.
"""
import base64
import importlib.util
import json
import unittest
from pathlib import Path

STAGE = Path(__file__).resolve().parents[4]
DECODER = STAGE / "decoders/Python/apps/TunnelDOOM_VPN/codec.py"
SERVER = STAGE / "decoders/Python/apps/TunnelDOOM_VPN/server_catalog_decoder.py"
FIXTURE = Path(__file__).resolve().parent / "fixtures/catalog_synthetic.json"


def load_decoder():
    spec = importlib.util.spec_from_file_location("td435_codec", DECODER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def build_envelope(codec, obj: dict) -> bytes:
    plain = "0123456789abcdef0123456789abcdef" + json.dumps(obj)
    raw = bytes(b ^ codec.CATALOG_KEY[i % 32]
                for i, b in enumerate(plain.encode("utf-8")))
    return base64.b64encode(raw)


class TunnelDoom435Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.codec = load_decoder()
        cls.plain = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_envelope_round_trip(self):
        # Real catalogs store the SERVER_FIELDS encrypted (AES-CBC, zero
        # IV); the fixture holds cleartext, so encrypt it first.
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        import copy
        plain = copy.deepcopy(self.plain)
        for server in plain["Servers"]:
            for name in self.codec.SERVER_FIELDS & server.keys():
                raw = AES.new(self.codec.FIELD_KEY, AES.MODE_CBC,
                              iv=b"\0" * 16).encrypt(
                                  pad(server[name].encode("utf-8"), 16))
                server[name] = base64.b64encode(raw).decode("ascii")
        doc = self.codec.decode_catalog(build_envelope(self.codec, plain))
        self.assertEqual(doc["Version"], "9.9")
        self.assertEqual(doc["Servers"][0]["Name"], "TEST-SERVER-1")
        self.assertEqual(doc["Servers"][0]["ServerIP"], "203.0.113.10")
        self.assertEqual(doc["Servers"][0]["ServerUser"], "test-user")

    def test_field_round_trip(self):
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        raw = AES.new(self.codec.FIELD_KEY, AES.MODE_CBC,
                      iv=b"\0" * 16).encrypt(pad(b"test-secret", 16))
        blob = base64.b64encode(raw).decode("ascii")
        self.assertEqual(self.codec.decode_field(blob), "test-secret")
        self.assertEqual(self.codec.decode_field(""), "")

    def test_bad_input_rejected(self):
        for bad in (b"garbage", b"", b"AAAA"):
            with self.subTest(bad=bad), self.assertRaises(self.codec.DecodeError):
                self.codec.decode_catalog(bad)

    def test_new_host_constant(self):
        text = SERVER.read_text(encoding="utf-8")
        self.assertIn('SOURCE = "https://free.tunneldoom.space/config.json"', text)
        # The old host may only appear in the docstring (as history), never
        # as the SOURCE constant.
        self.assertNotIn('SOURCE = "https://web.tunneldoom.space/config.json"', text)

    def test_no_real_credentials_in_fixture(self):
        raw = FIXTURE.read_text(encoding="utf-8")
        self.assertIn("203.0.113.10", raw)  # TEST-NET only
        self.assertIn("test-user", raw)


if __name__ == "__main__":
    unittest.main()
