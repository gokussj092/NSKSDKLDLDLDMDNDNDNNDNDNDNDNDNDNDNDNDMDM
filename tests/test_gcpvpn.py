"""GCP VPN 1.1 cloud catalog: synthetic fixtures through the real worker.

The catalog reuses the shared RENZ route (decoders/Python/renz.py,
profile ``gcpvpn``); fixtures are built with the inverse generators in
tests/test_renz_family.py plus small local main/sensitive envelope
builders. All values are fictitious (test.invalid); no live catalog
bytes or decrypted credentials are stored here.
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

from decoders.Python.apps.GCP_VPN import codec, file_decoder
from decoders.Python.apps.GCP_VPN import server_catalog_decoder as catalog
from decoders.Python import renz
from cloud.workers.python.engine import decode_provider_catalog
from tests.test_renz_family import profile_fixture, special_fixture, xxtea_encrypt

ROOT = Path(__file__).resolve().parents[1]
PUBKEY_HEX = "0123456789abcdef" * 4  # 64-char hex SlowDNS public key


def main_fixture(profile: str, clear: str) -> str:
    """One nested field envelope in the generic RENZ main mode."""
    spec = renz.RENZ_KEYS[profile]
    key = hashlib.sha256(spec["KEY_SEED"]).digest()[:16]
    transformed = bytes((b + 2) & 255 for b in clear.encode("utf-8"))
    blob = xxtea_encrypt(transformed, key)
    return base64.b64encode(
        AES.new(key, AES.MODE_CBC, iv=spec["IV"]).encrypt(pad(blob, 16))
    ).decode("ascii")


def sensitive_fixture(profile: str, clear: str) -> str:
    """One credential envelope in the RENZ sensitive (PBKDF2) mode."""
    src = renz.RENZ_KEYS[profile]
    key32 = hashlib.pbkdf2_hmac("sha256", src["KEY_SEED"], src["FIXED_SALT"], 100000, 32)
    nonce = bytes(range(16))
    ct = AES.new(key32, AES.MODE_CBC, nonce).encrypt(pad(clear.encode("utf-8"), 16))
    return base64.b64encode(xxtea_encrypt(nonce + ct, key32)).decode("ascii")


def build_catalog():
    """(raw envelope bytes, expected plaintext document)."""
    encrypted = {
        "Version": "3304-test",
        "Servers": [{
            "Name": main_fixture("gcpvpn", "Test Server"),
            "Subname": main_fixture("gcpvpn", "Test Subname"),
            "ServerIPHost": special_fixture("gcpvpn", "test.invalid"),
            "OpenVPNTCPPort": "443",
            "Username": sensitive_fixture("gcpvpn", "synthetic-user"),
            "Password": sensitive_fixture("gcpvpn", "synthetic-pass"),
            "SlowDNS": {
                "NSNameServer": main_fixture("gcpvpn", "ns1.test.invalid"),
                "PubKey": main_fixture("gcpvpn", PUBKEY_HEX),
            },
            "V2Ray": {"V2RayHost": special_fixture("gcpvpn", "v2.test.invalid")},
        }],
        "Networks": [{
            "Name": main_fixture("gcpvpn", "Test Network"),
            "SNIHost": special_fixture("gcpvpn", "sni.test.invalid"),
            "Payload": main_fixture("gcpvpn", "GET / HTTP/1.1"),
            "Info": main_fixture("gcpvpn", "Test info"),
        }],
        "Username": "",
        "Password": "",
        "Notes": "",
        "DirectUpdate": False,
        "ToastMessage": "",
    }
    expected = {
        "Version": "3304-test",
        "Servers": [{
            "Name": "Test Server",
            "Subname": "Test Subname",
            "ServerIPHost": "test.invalid",
            "OpenVPNTCPPort": "443",
            "Username": "synthetic-user",
            "Password": "synthetic-pass",
            "SlowDNS": {
                "NSNameServer": "ns1.test.invalid",
                "PubKey": PUBKEY_HEX,
            },
            "V2Ray": {"V2RayHost": "v2.test.invalid"},
        }],
        "Networks": [{
            "Name": "Test Network",
            "SNIHost": "sni.test.invalid",
            "Payload": "GET / HTTP/1.1",
            "Info": "Test info",
        }],
        "Username": "",
        "Password": "",
        "Notes": "",
        "DirectUpdate": False,
        "ToastMessage": "",
    }
    return profile_fixture("gcpvpn", encrypted), expected


RAW, EXPECTED = build_catalog()


class GcpVpnCatalogTests(unittest.TestCase):
    def test_synthetic_catalog_codec_cli_and_isolated_worker(self):
        self.assertEqual(json.loads(catalog.run(RAW)), EXPECTED)
        result = decode_provider_catalog("gcp-vpn", RAW)
        self.assertEqual(result["structuredJson"], EXPECTED)
        self.assertEqual(json.loads(result["rawText"]), EXPECTED)
        self.assertFalse(result["isPartial"])
        path = ROOT / "decoders/Python/apps/GCP_VPN/server_catalog_decoder.py"
        proc = subprocess.run(
            [sys.executable, str(path), "--stdin"], input=RAW,
            cwd="/tmp", capture_output=True, check=True)
        self.assertEqual(json.loads(proc.stdout), EXPECTED)

    def test_slowdns_pubkey_opens_with_main_mode(self):
        # Corrected diagnosis (2026-11-19): the live SlowDNS.PubKey values
        # open with the generic main mode to a 64-char hex key; speciale
        # returns non-printable garbage for them. The recursive pass must
        # therefore return the main-mode value, with no fallback change.
        doc = {"SlowDNS": {"PubKey": main_fixture("gcpvpn", PUBKEY_HEX)}}
        renz.renz_recursive_decrypt_main(doc, "gcpvpn")
        self.assertEqual(doc["SlowDNS"]["PubKey"], PUBKEY_HEX)
        self.assertNotEqual(
            renz.renz_decrypt_speciale(main_fixture("gcpvpn", PUBKEY_HEX), "gcpvpn"),
            PUBKEY_HEX)

    def test_file_route_canonical_renz(self):
        config = {"Server": "test.invalid", "Port": 443,
                  "Username": "synthetic-user", "Password": "synthetic-pass",
                  "Name": "GCPVPN sintetico", "Enabled": False}
        raw = profile_fixture("gcpvpn", config)
        self.assertEqual(json.loads(file_decoder.run(raw))["config"], config)
        self.assertEqual(json.loads(renz.decode_file(raw, ".gcpvpn"))["config"], config)

    def test_corruption_rejects_entire_catalog(self):
        no_servers = dict(json.loads(json.dumps(EXPECTED)))
        del no_servers["Servers"]
        for invalid in (b"", b"<html/>", RAW[:-5],
                        profile_fixture("gcpvpn", no_servers),
                        profile_fixture("7net", json.loads(json.dumps(EXPECTED)))):
            with self.subTest(length=len(invalid)):
                with self.assertRaises(codec.DecodeError):
                    catalog.run(invalid)
        with self.assertRaises(codec.DecodeError):
            catalog._NoRedirect().redirect_request(None, None, None, None, None, None)


if __name__ == "__main__":
    unittest.main()
