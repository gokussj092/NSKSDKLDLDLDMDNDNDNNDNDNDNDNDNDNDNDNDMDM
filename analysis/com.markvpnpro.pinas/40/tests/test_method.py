"""ANY VPN build 40: CJK desubstitution + API-key strip on synthetic data only.

No network, no real servers, no real credentials. The fixture is the expected
decrypted synthetic catalog (TEST-NET hosts). Run from the repo root:

    python3 analysis/com.markvpnpro.pinas/40/tests/test_method.py

Requires PyCryptodome (runtime dependency of the codec, pinned 3.23.0).
"""
import base64
import importlib.util
import json
import unittest
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

HERE = Path(__file__).resolve()
ROOT = HERE.parents[4]
FIXTURE = HERE.parent / "fixtures" / "synthetic_catalog.json"


def load_codec():
    path = ROOT / "decoders" / "Python" / "apps" / "ANY_VPN" / "codec.py"
    spec = importlib.util.spec_from_file_location("_any_vpn_codec_update", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AnyUpdateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.codec = load_codec()
        cls.expected = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.rev = {v: k for k, v in cls.codec.SUB.items()}

    def seal(self, text):
        return base64.b64encode(AES.new(
            self.codec.KEY, AES.MODE_CBC, bytes(16)).encrypt(pad(text.encode(), 16))).decode()

    def substitute(self, text):
        return "".join(self.rev.get(c, c) for c in text)

    def sealed_catalog(self):
        server = dict(self.expected["Servers"][0])
        network = dict(self.expected["Networks"][0])
        for row, fields in ((server, self.codec.SERVER_FIELDS),
                            (network, self.codec.NETWORK_FIELDS)):
            for key in fields & row.keys():
                row[key] = self.seal(self.substitute(row[key]))
        obj = {"Version": self.expected["Version"],
               "Servers": [server], "Networks": [network],
               "Username": self.expected["Username"],
               "Password": self.expected["Password"],
               "Notes": self.expected["Notes"],
               "config_url": self.seal(self.substitute("https://example.invalid/catalog")),
               "account_api": self.seal(self.substitute("https://example.invalid/account"))}
        return obj

    def test_desubstitute_roundtrip(self):
        for clean in ("45.81.5.149", "sumonbd", "GET / HTTP/1.1", "example.invalid", "127.0.0.1:1080"):
            self.assertEqual(self.codec.desubstitute(self.substitute(clean)), clean)
        self.assertEqual(self.codec.desubstitute("plain ascii 123"), "plain ascii 123")
        self.assertEqual(self.codec.desubstitute(""), "")

    def test_decode_catalog_desubstitutes_and_strips_api_keys(self):
        actual = self.codec.decode_catalog(self.seal(json.dumps(self.sealed_catalog())).encode())
        self.assertEqual(actual, self.expected)
        self.assertNotIn("config_url", actual)
        self.assertNotIn("account_api", actual)

    def test_decode_catalog_accepts_plain_json_with_sealed_fields(self):
        # Same sealed field values, but the envelope itself is plain JSON
        # (the app's Servers.js on-disk form), not a sealed envelope.
        obj = self.sealed_catalog()
        self.assertEqual(self.codec.decode_catalog(json.dumps(obj).encode()), self.expected)

    def test_decode_profile_dtk_roundtrip_with_substituted_fields(self):
        server = dict(self.expected["Servers"][0])
        network = dict(self.expected["Networks"][0])
        for row, fields in ((server, self.codec.SERVER_FIELDS),
                            (network, self.codec.NETWORK_FIELDS)):
            for key in fields & row.keys():
                row[key] = self.seal(self.substitute(row[key]))
        doc = {"server": json.dumps(server), "network": json.dumps(network)}
        actual = self.codec.decode_profile(self.seal(json.dumps(doc)).encode())
        self.assertEqual(actual["server"]["ServerIPHost"], "203.0.113.10")
        self.assertEqual(actual["server"]["ServerUser"], "testuser")
        self.assertEqual(actual["network"]["SNIHost"], "203.0.113.10")

    def test_rejects_invalid_encrypted_field(self):
        obj = self.sealed_catalog()
        obj["Servers"][0]["ServerIPHost"] = "not encrypted"
        with self.assertRaises(self.codec.DecodeError):
            self.codec.decode_catalog(self.seal(json.dumps(obj)).encode())

    def test_rejects_non_json_envelope(self):
        for data in (b"", b"not base64", b"AA"):
            with self.assertRaises(self.codec.DecodeError):
                self.codec.decode_catalog(data)


if __name__ == "__main__":
    unittest.main()
