"""AM Tunnel Lite AM (63) cloud catalog + pdrv2 file route: synthetic fixtures.

The catalog uses a STANDALONE codec (decoders/Python/apps/AM_Tunnel_Lite/
codec.py): Base64 -> XXTEA with the static key '...|...' and the
NON-STANDARD delta 0x9E5729B1 (literal -1638454863 from Ltm.b). The
standard delta 0x9E3779B9 does NOT open it. No renz.py profile is
registered. Fixtures are built with the codec's own inverse generator
(xxtea_encrypt) or taken from the dossier's synthetic fixtures
(analysis/app.vpn.amtunnellite/63/tests/fixtures/, Version "9.9" /
"8.8", TEST-NET-1 IPs only). All values are fictitious; no live catalog
bytes or decrypted credentials are stored here.

Live catalog (dossier, 2026-11-22): Version 4.6, 172 free servers
(3,341 endpoints), 137 payloads, 0/0/0 premium/vip/private, raw body
163,960 B, SHA-256 38cca537...49da. Run with --live to re-verify the
live download + decode (structure and counts only).
"""
import base64
import json
import subprocess
import sys
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from decoders.Python.apps.AM_Tunnel_Lite import codec, file_decoder
from decoders.Python.apps.AM_Tunnel_Lite import server_catalog_decoder as catalog
from cloud.workers.python.engine import DecodeFailure, decode_file, decode_provider_catalog

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = json.loads((ROOT / "tests/golden/amtunnel_catalog_vectors.json").read_text())
V = GOLDEN  # {"catalog": synthetic Base64 blob, "expected": synthetic doc}

SYNTHETIC_DOC = {
    "Version": "9.9",
    "UpdaterLink": "",
    "Premium_servers": [],
    "Vip_servers": [],
    "Private_servers": [],
    "Username": "dGVzdA==",
    "Password": "dGVzdA==",
    "UDPVersion": "v2",
    "Free_servers": [{
        "server_name": "Testland - Demo 1",
        "server_host": "demo1.example.invalid;demo2.example.invalid",
        "server_port": "",
        "server_udp_port": "",
        "ssl_port": "",
        "category": "ocsudp",
        "username": "",
        "password": "",
        "custom_cert": "",
    }],
    "Payloads": [{
        "friendly_name": "Test Payload",
        "payload": "GET http://192.0.2.1/ HTTP/1.1",
        "sausage": "",
        "host": "Pulled",
        "port": "Pulled",
        "dothost": "",
        "message": "",
        "method": "http",
        "category": "ocsslow",
        "query": "normal",
        "sslws": "false",
    }],
    "Changelogs": "test",
}


def encrypt_doc(doc):
    return base64.b64encode(
        codec.xxtea_encrypt(json.dumps(doc, ensure_ascii=False).encode("utf-8"))
    ).decode("ascii")


class AmTunnelLiteCatalogTests(unittest.TestCase):
    def test_synthetic_vector_codec_worker_and_cli(self):
        data = V["catalog"].encode()
        expected = V["expected"]
        self.assertEqual(codec.decode_catalog(data), expected)
        self.assertEqual(json.loads(catalog.run(data)), expected)
        result = decode_provider_catalog("am-tunnel-lite", data)
        self.assertEqual(result["structuredJson"], expected)
        self.assertEqual(json.loads(result["rawText"]), expected)
        self.assertFalse(result["isPartial"])

    def test_round_trip_generated_synthetic(self):
        blob = encrypt_doc(SYNTHETIC_DOC)
        self.assertEqual(codec.decode_catalog_b64(blob), SYNTHETIC_DOC)
        self.assertEqual(json.loads(catalog.run(blob.encode())), SYNTHETIC_DOC)

    def test_cli_stdin_outside_repository(self):
        p = subprocess.run([sys.executable, str(ROOT / "decoders/Python/apps/AM_Tunnel_Lite/server_catalog_decoder.py"), "--stdin"],
                           input=V["catalog"].encode(), cwd="/tmp", capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        self.assertEqual(json.loads(p.stdout), V["expected"])

    def test_standard_delta_rejects_vector(self):
        raw = base64.b64decode(V["catalog"])
        std = codec.xxtea_decrypt(raw, delta=0x9E3779B9)
        sample = json.dumps(V["expected"], ensure_ascii=False).encode("utf-8")
        self.assertTrue(std is None or std != sample)

    def test_invalid_sections_lengths_limits_and_redirects(self):
        raw = base64.b64decode(V["catalog"])
        for data in [b"", b"<html/>", b"not-base64!!!", base64.b64encode(raw[:-1]),
                     V["catalog"][:-12].encode(), b"x" * (catalog.MAX_BYTES + 1)]:
            with self.subTest(data=data[:20]):
                with self.assertRaises(catalog.DecodeError):
                    catalog.run(data)
        with self.assertRaises(urllib.error.HTTPError):
            codec._NoRedirect().redirect_request(
                urllib.request.Request("https://example.invalid/"),
                None, 302, "Found", {}, "https://example.invalid/")

    def test_sanitize_redacts_credentials_and_ips(self):
        dirty = json.loads(json.dumps(SYNTHETIC_DOC))
        clean = codec.sanitize_catalog(dirty)
        self.assertEqual(clean["Username"], "[redacted]")
        self.assertEqual(clean["Password"], "[redacted]")
        self.assertEqual(clean["Free_servers"][0]["server_host"], "[redacted]")
        self.assertEqual(clean["Free_servers"][0]["server_host_count"], 2)
        self.assertNotIn("192.0.2.1", clean["Payloads"][0]["payload"])

    def test_self_tests(self):
        self.assertEqual(codec.self_test(), 0)
        self.assertEqual(file_decoder.self_test(), 0)


class AmTunnelLiteFileTests(unittest.TestCase):
    def test_pdrv2_round_trip_and_file_route(self):
        blob = encrypt_doc({**SYNTHETIC_DOC, "Version": "8.8"})
        doc = file_decoder.decode_pdrv2_bytes(blob.encode())
        self.assertEqual(doc["Version"], "8.8")
        self.assertEqual(json.loads(file_decoder.run(blob.encode())), doc)
        self.assertEqual(decode_file("pdtv2", blob.encode())["structuredJson"], doc)

    def test_pdrv2_rejects_corrupt_and_html(self):
        for bad in (base64.b64encode(b"\x00" * 32), b"<html/>", b"", b"not-base64!!!"):
            with self.subTest(bad=bad[:20]):
                with self.assertRaises(codec.DecodeError):
                    file_decoder.run(bad)
        with self.assertRaises(DecodeFailure):
            decode_file("pdtv2", b"")

    def test_wg_conf_valid_and_negatives(self):
        h1 = base64.b64encode(bytes(range(32))).decode()
        h2 = base64.b64encode(bytes(range(32, 64))).decode()
        good = "Endpoint = 192.0.2.1\nHash1 = %s\nHash2 = %s\n" % (h1, h2)
        parsed = file_decoder.parse_wg_conf(good)
        self.assertEqual(parsed["Endpoint"], "192.0.2.1")
        self.assertEqual(parsed["Hash1"], bytes(range(32)))
        self.assertEqual(parsed["Hash2"], bytes(range(32, 64)))
        for bad in (
                "Endpoint = not-an-ip\nHash1 = %s\nHash2 = %s\n" % (h1, h2),
                "Endpoint = 192.0.2.1\nHash1 = AA==\nHash2 = %s\n" % h2,
                good + "Extra = x\n"):
            with self.subTest(bad=bad[:30]):
                with self.assertRaises(ValueError):
                    file_decoder.parse_wg_conf(bad)


if __name__ == "__main__":
    live = "--live" in sys.argv
    if live:
        sys.argv.remove("--live")
    result = unittest.main(exit=False)
    if live and result.result.wasSuccessful():
        body = catalog.download()
        doc = codec.decode_catalog(body)
        print("LIVE: Version %s, %d servidores libres, %d payloads, %d B crudos"
              % (doc.get("Version"), len(doc.get("Free_servers", [])),
                 len(doc.get("Payloads", [])), len(body)))
        assert doc.get("Version") == "4.6"
        assert len(doc.get("Free_servers", [])) == 172
        assert len(doc.get("Payloads", [])) == 137
    sys.exit(0 if result.result.wasSuccessful() else 1)
