"""Ways Tunnel 18.1 live catalog + wyst:// tweaks: synthetic fixtures.

The catalog uses the glyph route (``decoders/Python/apps/Ways_Tunnel/
waystunnel.py``): glyphs -> Base64 -> AES-256-CBC (key SHA-256 of the
upper-case hex of the app password, zero IV, PKCS#7). The codec
validates the structure and redacts everything that is not catalog
data (server credentials, tokens, per-server v2rayJson/OpenVPN
configs, SlowDns, the WhatsApp invite link). Fixtures are built
below with literal synthetic values (test.invalid); no live catalog
bytes, session values or decrypted credentials are stored here.

The ``wyst://`` tweak route is VERIFIED_SYNTHETIC: the AES/CBC/
IV-zero construction with ``tweakdam0n`` is reconstructed from the
DEX and the round-trip below is synthetic; no real ``wyst://``
sample has been supplied yet.
"""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from decoders.Python.apps.Ways_Tunnel import waystunnel
from decoders.Python.apps.Ways_Tunnel import server_catalog_decoder as catalog
from decoders.Python.apps.Ways_Tunnel import text_decoder
from cloud.workers.python.engine import decode_provider_catalog

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = json.loads((ROOT / "tests/golden/waystunnel_catalog_vectors.json").read_text())
GOLDEN_RAW = GOLDEN["catalog"].encode("utf-8")  # worker input is the glyph text
GOLDEN_EXPECTED = GOLDEN["expected"]


def build_catalog():
    """(raw glyph bytes, expected redacted document)."""
    raw = {
        "Version": "1.0.49",
        "ReleaseNotes": "Synthetic test catalog",
        "WhatsApp": "https://example.invalid/synthetic-invite",
        "Servers": [{
            "Name": "Test Server MX 1", "Flag": "ma",
            "MyServer": "SSH/DIRECT | PROXY", "ServerPort": "80",
            "SSLPort": "443", "ProxyPort": "80", "udpbuffer": "8888",
            "udpdown": "100", "udpup": "100",
            "supportedProtocol": "ssh,ssl_ssh,v2ray",
            "ServerIP": "203.0.113.10", "ServerUser": "synthetic-user",
            "ServerPass": "synthetic-pass-must-be-stripped",
            "ProxyIP": "203.0.113.11", "SlowChave": "synthetic-slow-key",
            "TokenAuth": "synthetic-token", "NameServer": "203.0.113.12",
            "udpserver": "203.0.113.13", "udpobfs": "synthetic-obfs",
            "udpauth": "synthetic-udpauth",
            "OpenVPNConfig": "client\nsynthetic-ovpn",
            "v2rayJson": "vless://synthetic-uuid@test.invalid:443",
        }],
        "Networks": [{
            "Name": "Test Network 1", "Flag": "mz", "MyServer": "Test",
            "Payload": "CONNECT [host_port] [protocol][crlf]",
            "SNI": "example.com", "UpSlot": "8", "DownSlot": "12",
            "Modo": "ssl_ssh", "SlowDns": "203.0.113.30",
            "OpenVPNConfig": "client\nsynthetic",
            "v2rayJson": "vless://synthetic@test.invalid:443",
        }, {
            "Name": "Test Network 2", "Flag": "br", "MyServer": "Test 2",
            "Payload": "", "SNI": "", "UpSlot": "4", "DownSlot": "6",
            "Modo": "proxy", "SlowDns": "", "OpenVPNConfig": "",
            "v2rayJson": "",
        }],
    }
    expected = {
        "Version": "1.0.49",
        "ReleaseNotes": "Synthetic test catalog",
        "Servers": [{
            "Name": "Test Server MX 1", "Flag": "ma",
            "MyServer": "SSH/DIRECT | PROXY", "ServerPort": "80",
            "SSLPort": "443", "ProxyPort": "80", "udpbuffer": "8888",
            "udpdown": "100", "udpup": "100",
            "supportedProtocol": "ssh,ssl_ssh,v2ray",
        }],
        "Networks": [{
            "Name": "Test Network 1", "Flag": "mz", "MyServer": "Test",
            "Payload": "CONNECT [host_port] [protocol][crlf]",
            "SNI": "example.com", "UpSlot": "8", "DownSlot": "12",
            "Modo": "ssl_ssh",
        }, {
            "Name": "Test Network 2", "Flag": "br", "MyServer": "Test 2",
            "Payload": "", "SNI": "", "UpSlot": "4", "DownSlot": "6",
            "Modo": "proxy",
        }],
    }
    glyphs = waystunnel.encode_config(json.dumps(raw, ensure_ascii=False))
    return glyphs.encode("utf-8"), expected


RAW, EXPECTED = build_catalog()

TWEAK_SAMPLE = {"Name": "SyntheticTweak", "Modo": "ssl_ssh",
                "Payload": "CONNECT [host_port] [protocol][crlf]",
                "SNI": "example.com"}


class WaysTunnelCatalogTests(unittest.TestCase):
    def test_synthetic_catalog_codec_cli_and_isolated_worker(self):
        self.assertEqual(json.loads(catalog.run(RAW)), EXPECTED)
        result = decode_provider_catalog("ways-tunnel", RAW)
        self.assertEqual(result["structuredJson"], EXPECTED)
        self.assertEqual(json.loads(result["rawText"]), EXPECTED)
        self.assertFalse(result["isPartial"])
        path = ROOT / "decoders/Python/apps/Ways_Tunnel/server_catalog_decoder.py"
        proc = subprocess.run(
            [sys.executable, str(path), "--stdin"], input=RAW,
            cwd="/tmp", capture_output=True, check=True)
        self.assertEqual(json.loads(proc.stdout), EXPECTED)

    def test_golden_vector_opens_through_codec(self):
        self.assertEqual(json.loads(catalog.run(GOLDEN_RAW)), GOLDEN_EXPECTED)

    def test_result_has_no_credentials_or_download_apis(self):
        rendered = catalog.run(RAW)
        for forbidden in ("raw.githubusercontent.com", "waystunnel/politicas",
                          "ServerIP", "ServerUser", "ServerPass", "ProxyIP",
                          "SlowChave", "TokenAuth", "NameServer", "udpserver",
                          "udpobfs", "udpauth", "OpenVPNConfig", "v2rayJson",
                          "SlowDns", "WhatsApp", "synthetic-pass",
                          "synthetic-token", "203.0.113",
                          '"script":', "source_script", "privateKey",
                          "decoders/Python/"):
            self.assertNotIn(forbidden, rendered)
        doc = json.loads(rendered)
        self.assertEqual(sorted(doc.keys()), sorted(
            ["Version", "ReleaseNotes", "Servers", "Networks"]))
        self.assertEqual(
            sorted(doc["Servers"][0].keys()),
            sorted(["Flag", "MyServer", "Name", "ProxyPort", "SSLPort",
                    "ServerPort", "supportedProtocol", "udpbuffer",
                    "udpdown", "udpup"]))
        self.assertEqual(
            sorted(doc["Networks"][0].keys()),
            sorted(["DownSlot", "Flag", "Modo", "MyServer", "Name",
                    "Payload", "SNI", "UpSlot"]))

    def test_tweak_round_trip_synthetic(self):
        link = waystunnel.encrypt_tweak(
            json.dumps(TWEAK_SAMPLE, ensure_ascii=False))
        self.assertTrue(link.startswith("wyst://"))
        doc = json.loads(text_decoder.decode_text(link))
        self.assertEqual(doc["application"], "Ways Tunnel 18.1")
        self.assertEqual(doc["protocol"], "wyst://")
        self.assertEqual(doc["config"], TWEAK_SAMPLE)
        # Foreign scheme: not a Ways link, never a fallback.
        self.assertIsNone(text_decoder.decode_text("vmess://synthetic"))
        self.assertIsNone(text_decoder.decode_text("wyst://"))
        # Corrupt tweak: undecodable link, never a fallback.
        self.assertIsNone(text_decoder.decode_text(link[:-4] + "AAAA"))
        # Tweaks take no password credential.
        with self.assertRaises(text_decoder.WaysDecodeError) as ctx:
            text_decoder.decode_text(link, password="x")
        self.assertEqual(ctx.exception.code, "CREDENTIALS_NOT_ALLOWED")

    def test_corruption_rejects_entire_catalog(self):
        glyphs = RAW.decode("utf-8")
        odd = glyphs[:-1]
        bad_glyph = "A" + glyphs[1:]
        no_version = dict(json.loads(waystunnel.decode_config(glyphs)))
        del no_version["Version"]
        no_servers = json.loads(waystunnel.decode_config(glyphs))
        no_servers["Servers"] = []
        no_networks = json.loads(waystunnel.decode_config(glyphs))
        no_networks["Networks"] = []
        no_name = json.loads(waystunnel.decode_config(glyphs))
        del no_name["Servers"][0]["Name"]
        for invalid in (b"", b"<html/>", odd.encode("utf-8"),
                        bad_glyph.encode("utf-8"),
                        waystunnel.encode_config(
                            json.dumps(no_version)).encode("utf-8"),
                        waystunnel.encode_config(
                            json.dumps(no_servers)).encode("utf-8"),
                        waystunnel.encode_config(
                            json.dumps(no_networks)).encode("utf-8"),
                        waystunnel.encode_config(
                            json.dumps(no_name)).encode("utf-8"),
                        waystunnel.encode_config(
                            '{"Version": "1.0.49", "Version": "1.0.49", '
                            '"Servers": [{"Name": "x"}], '
                            '"Networks": [{"Name": "y"}]}').encode("utf-8")):
            with self.subTest(length=len(invalid)):
                with self.assertRaises(catalog.DecodeError):
                    catalog.run(invalid)

    def test_live_catalog_opens_when_env_provides_glyphs(self):
        """Optional live check: WAYS_REAL_CATALOG=<glyph text>.

        Skipped by default; the real glyph body is never stored in Git.
        """
        glyphs = os.environ.get("WAYS_REAL_CATALOG")
        if not glyphs:
            self.skipTest("WAYS_REAL_CATALOG not set (live check skipped)")
        doc = catalog.decode_catalog(glyphs.encode("utf-8"))
        self.assertEqual(doc["Version"], "1.0.49")
        self.assertEqual(len(doc["Servers"]), 5)
        self.assertEqual(len(doc["Networks"]), 78)


if __name__ == "__main__":
    unittest.main()
