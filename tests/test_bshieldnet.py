"""B SHIELD NET 2.9 cloud catalog: synthetic fixtures through the real worker.

The catalog reuses the shared RENZ route (decoders/Python/renz.py)
with EXPLICIT dispatch to the existing profile ``bshield`` -- the
profile, the ``.bshield`` suffix and the ``bshieldnet://`` /
``bshield://`` schemes were already registered in ``renz.py`` (no
new profile, no new key material). Fixtures are built with the
inverse generator in ``bshieldnet.py`` (``encrypt_profile``), which
is verified byte-identical against the live blob. All values are
fictitious (test.invalid); no live catalog bytes or decrypted
credentials are stored here.

File/text coverage adapts the 8 round-trip tests of the deliverable
(``~/workspace/catalogs/bshieldnet/tests/``): the explicit dispatch
is exercised here through ``file_decoder.run`` /
``file_decoder.decode_text``, the canonical C0 file route
(``decode_file('bshield', ...)``) and the ``text_bridge.dispatch``
end-to-end route.

The live catalog (Version 7.34, 90 servers, 792 networks) is
VERIFIED_REAL; files and texts stay VERIFIED_SYNTHETIC until a real
``.bshield`` export or a real ``bshieldnet://`` link is supplied.
"""
import base64
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from decoders.Python.apps.BShieldNet import bshieldnet, codec, file_decoder
from decoders.Python.apps.BShieldNet import server_catalog_decoder as catalog
from decoders.Python import renz
from cloud.workers.python.engine import decode_file, decode_provider_catalog
from cloud.workers.python.text_bridge import dispatch as text_dispatch

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = json.loads((ROOT / "tests/golden/bshieldnet_catalog_vectors.json").read_text())
GOLDEN_RAW = GOLDEN["catalog"].encode("utf-8")
GOLDEN_EXPECTED = GOLDEN["expected"]

# Synthetic profile: fictitious values only (test.invalid / test-user).
TEST_PROFILE = {
    "Version": "7.34",
    "Servers": [{
        "Name": "TEST SERVER",
        "ServerIPHost": "test.invalid",
        "Subname": "Test",
        "OpenVPNTCPPort": "1194",
        "OpenVPNSSLPort": "443",
        "Protocol": 0,
        "flag": "mx",
        "Username": "test-user",
        "Password": "test-pass",
    }],
    "Networks": [{
        "Name": "TEST PAYLOAD",
        "SNIHost": "test.invalid",
        "Payload": "GET / HTTP/1.1[crlf]Host: test.invalid[crlf][crlf]",
        "ServerProtocol": 0,
        "TunnelType": 7,
    }],
}

RAW = bshieldnet.encrypt_profile(TEST_PROFILE)
EXPECTED = TEST_PROFILE


def _encrypt_with_profile(profile: str, config: dict) -> bytes:
    """Same outer envelope as bshieldnet.encrypt_profile, other profile."""
    data = json.dumps(config, ensure_ascii=False).encode("utf-8")
    spec = renz.RENZ_KEYS[profile]
    key = hashlib.sha256(spec["KEY_SEED"]).digest()[:16]
    transformed = bytes((b + 2) & 255 for b in data)
    blob = bshieldnet._xxtea_encrypt_custom(transformed, key)
    cipher = AES.new(key, AES.MODE_CBC, iv=spec["IV"])
    return base64.b64encode(cipher.encrypt(pad(blob, 16)))


class BShieldNetCatalogTests(unittest.TestCase):
    def test_synthetic_catalog_codec_cli_and_isolated_worker(self):
        self.assertEqual(json.loads(catalog.run(RAW)), EXPECTED)
        result = decode_provider_catalog("bshield-net", RAW)
        self.assertEqual(result["structuredJson"], EXPECTED)
        self.assertEqual(json.loads(result["rawText"]), EXPECTED)
        self.assertFalse(result["isPartial"])
        path = ROOT / "decoders/Python/apps/BShieldNet/server_catalog_decoder.py"
        proc = subprocess.run(
            [sys.executable, str(path), "--stdin"], input=RAW,
            cwd="/tmp", capture_output=True, check=True)
        self.assertEqual(json.loads(proc.stdout), EXPECTED)

    def test_golden_vector_opens_through_codec(self):
        self.assertEqual(json.loads(catalog.run(GOLDEN_RAW)), GOLDEN_EXPECTED)

    def test_result_has_no_download_api_or_script_paths(self):
        rendered = catalog.run(RAW)
        for forbidden in ("raw.githubusercontent.com/snapb", "B-SHIELD-NET-2026",
                          "decoders/Python/", '"script":', "source_script",
                          "privateKey"):
            self.assertNotIn(forbidden, rendered)
        doc = json.loads(rendered)
        self.assertEqual(sorted(doc.keys()), sorted(
            ["Version", "Servers", "Networks"]))

    def test_file_round_trip_canonical_renz(self):
        self.assertEqual(json.loads(file_decoder.run(RAW))["config"], TEST_PROFILE)
        self.assertEqual(
            json.loads(file_decoder.run(
                ("bshieldnet://" + RAW.decode("ascii")).encode("utf-8")))["config"],
            TEST_PROFILE)
        self.assertEqual(
            json.loads(file_decoder.run(
                ("BSHIELDNET://" + RAW.decode("ascii")).encode("utf-8")))["config"],
            TEST_PROFILE)
        # Canonical C0 file route: .bshield -> decoders/Python/renz.py.
        self.assertEqual(decode_file("bshield", RAW)["structuredJson"]["config"],
                         TEST_PROFILE)
        with self.assertRaises(codec.DecodeError):
            file_decoder.run(b"AAAAAAAAAAAAAAAAAAAAAA==")
        with self.assertRaises(codec.DecodeError):
            file_decoder.run(b"")

    def test_text_link_round_trip_canonical_renz(self):
        payload = RAW.decode("ascii")
        for scheme in ("bshieldnet://", "bshield://"):
            link = scheme + payload
            parsed = json.loads(file_decoder.decode_text(link))
            self.assertEqual(parsed["application"], "RENZ / BSHIELD")
            self.assertEqual(parsed["protocol"], scheme)
            self.assertEqual(parsed["config"], TEST_PROFILE)
            self.assertEqual(json.loads(text_dispatch(link)), parsed)
            self.assertEqual(
                json.loads(file_decoder.decode_text(scheme.upper() + payload))["config"],
                TEST_PROFILE)
            self.assertEqual(
                json.loads(text_dispatch(scheme.upper() + payload))["config"],
                TEST_PROFILE)
            self.assertEqual(
                json.loads(file_decoder.run(link.encode("utf-8")))["config"],
                TEST_PROFILE)
        for bad in ("bshieldnet://AAAAAAAAAAAAAAAAAAAAAA==",
                    "bshield://AAAAAAAAAAAAAAAAAAAAAA==",
                    "bshieldnet://" + _encrypt_with_profile("7net", TEST_PROFILE).decode("ascii"),
                    "vless://" + payload):
            with self.subTest(bad=bad[:22]):
                self.assertIsNone(file_decoder.decode_text(bad))
                self.assertIsNone(text_dispatch(bad))
        self.assertIsNone(file_decoder.decode_text("bshieldnet://"))
        self.assertIsNone(file_decoder.decode_text("bshield://"))
        self.assertIsNone(file_decoder.decode_text(""))

    def test_corruption_rejects_entire_catalog(self):
        no_servers = dict(json.loads(json.dumps(EXPECTED)))
        del no_servers["Servers"]
        no_networks = dict(json.loads(json.dumps(EXPECTED)))
        no_networks["Networks"] = []
        for invalid in (b"", b"<html/>", RAW[:-5],
                        bshieldnet.encrypt_profile(no_servers),
                        bshieldnet.encrypt_profile(no_networks),
                        _encrypt_with_profile("7net", json.loads(json.dumps(EXPECTED)))):
            with self.subTest(length=len(invalid)):
                with self.assertRaises(codec.DecodeError):
                    catalog.run(invalid)
        with self.assertRaises(codec.DecodeError):
            catalog._NoRedirect().redirect_request(None, None, None, None, None, None)


if __name__ == "__main__":
    unittest.main()
