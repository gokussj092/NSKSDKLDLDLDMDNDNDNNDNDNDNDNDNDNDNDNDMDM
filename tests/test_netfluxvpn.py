"""NetFlux VPN 1.1 cloud catalog: synthetic fixtures through the real worker.

The catalog reuses the shared RENZ route (decoders/Python/renz.py)
with EXPLICIT dispatch to the existing profile ``gcpvpn`` -- same key
material as the live NetFlux catalog, no ``netflux`` profile
registered in renz.py (a server-side update must not touch the APK).
Fixtures are built with the inverse generators in
tests/test_renz_family.py plus small local main/sensitive envelope
builders. All values are fictitious (test.invalid); no live catalog
bytes or decrypted credentials are stored here.

File/text coverage adapts the 7 round-trip tests of the deliverable
``netflux.py`` (~/workspace/catalogs/netfluxvpn/tests/): the explicit
dispatch is exercised here through ``file_decoder.run`` /
``file_decoder.decode_text`` and the ``text_bridge.dispatch``
end-to-end route, plus the C8 engine file route.
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

from decoders.Python.apps.NETFLUX_VPN import codec, file_decoder
from decoders.Python.apps.NETFLUX_VPN import server_catalog_decoder as catalog
from decoders.Python import renz
from cloud.workers.python.engine import decode_file, decode_provider_catalog
from cloud.workers.python.text_bridge import dispatch as text_dispatch
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


class NetfluxVpnCatalogTests(unittest.TestCase):
    def test_synthetic_catalog_codec_cli_and_isolated_worker(self):
        self.assertEqual(json.loads(catalog.run(RAW)), EXPECTED)
        result = decode_provider_catalog("netflux-vpn", RAW)
        self.assertEqual(result["structuredJson"], EXPECTED)
        self.assertEqual(json.loads(result["rawText"]), EXPECTED)
        self.assertFalse(result["isPartial"])
        path = ROOT / "decoders/Python/apps/NETFLUX_VPN/server_catalog_decoder.py"
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
                  "Name": "NetFlux sintetico", "Enabled": False}
        raw = profile_fixture("gcpvpn", config)
        self.assertEqual(json.loads(file_decoder.run(raw))["config"], config)
        self.assertEqual(
            json.loads(file_decoder.run(
                ("netfluxvpn://" + raw.decode("ascii")).encode("utf-8")))["config"],
            config)
        self.assertEqual(
            json.loads(file_decoder.run(
                ("NETFLUXVPN://" + raw.decode("ascii")).encode("utf-8")))["config"],
            config)
        self.assertEqual(decode_file("netflux", raw)["structuredJson"]["config"],
                         config)
        with self.assertRaises(codec.DecodeError):
            file_decoder.run(b"AAAAAAAAAAAAAAAAAAAAAA==")
        with self.assertRaises(codec.DecodeError):
            file_decoder.run(b"")


    def test_text_link_round_trip_canonical_renz(self):
        # Adapted from the deliverable netflux.py round-trip (7 tests):
        # the netfluxvpn:// scheme opens through the explicit dispatch in
        # file_decoder.decode_text (shared 'gcpvpn' profile, no 'netflux'
        # registration in renz.py) and end to end through
        # text_bridge.dispatch; a file carrying the scheme prefix opens
        # through file_decoder.run; garbage / a wrong scheme prefix / a
        # wrong-profile envelope are None.
        config = {"Server": "test.invalid", "Port": 443,
                  "Username": "synthetic-user", "Password": "synthetic-pass",
                  "Name": "NetFlux sintetico", "Enabled": False}
        payload = profile_fixture("gcpvpn", config).decode("ascii")
        link = "netfluxvpn://" + payload
        parsed = json.loads(file_decoder.decode_text(link))
        self.assertEqual(parsed["application"], "RENZ / NETFLUX")
        self.assertEqual(parsed["protocol"], "netfluxvpn://")
        self.assertEqual(parsed["config"], config)
        self.assertEqual(json.loads(text_dispatch(link)), parsed)
        self.assertEqual(
            json.loads(file_decoder.decode_text("NETFLUXVPN://" + payload))["config"],
            config)
        self.assertEqual(json.loads(text_dispatch("NETFLUXVPN://" + payload))["config"],
                         config)
        self.assertEqual(
            json.loads(file_decoder.run(link.encode("utf-8")))["config"],
            config)
        for bad in ("netfluxvpn://AAAAAAAAAAAAAAAAAAAAAA==",
                    "netflux:// " + payload,
                    "netfluxvpn://" + profile_fixture("7net", config).decode("ascii")):
            with self.subTest(bad=bad[:22]):
                self.assertIsNone(file_decoder.decode_text(bad))
                self.assertIsNone(text_dispatch(bad))
        self.assertIsNone(file_decoder.decode_text("netfluxvpn://"))
        self.assertIsNone(file_decoder.decode_text(""))

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
