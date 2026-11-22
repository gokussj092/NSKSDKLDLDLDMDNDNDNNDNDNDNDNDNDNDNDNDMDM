"""PM Tunnel Lite 1.0 cloud catalog: synthetic fixtures through the real worker.

The catalog uses a STANDALONE codec (decoders/Python/apps/PM_Tunnel_Lite/
codec.py): same crypto structure and XXTEA delta as the shared RENZ route,
but different key material, so no renz.py profile is registered and the
canonical RENZ route cannot serve this app. Fixtures are built with the
codec's own inverse generators (encrypt_mode0 / encrypt_special /
encrypt_sensitive). All values are fictitious (test.invalid); no live
catalog bytes or decrypted credentials are stored here.

The bundled fallback catalog (res/ae/e.js, Version "1.0", placeholder
server, host 0.0.0.0) is embedded below as a known-answer vector: it
shipped inside the APK and carries no real credentials.
"""
import json
import struct
import subprocess
import sys
import unittest
from pathlib import Path

from decoders.Python.apps.PM_Tunnel_Lite import codec, file_decoder
from decoders.Python.apps.PM_Tunnel_Lite import server_catalog_decoder as catalog
from cloud.workers.python.engine import decode_provider_catalog
from cloud.workers.python.text_bridge import dispatch as text_dispatch

ROOT = Path(__file__).resolve().parents[1]
FIXED_IV = bytes(range(16))

# Bundled fallback catalog res/ae/e.js (Version "1.0", 1 placeholder
# server, host 0.0.0.0). No real credentials.
EJS_B64 = (
    "Og0GVqc7nPHL2ok6vkyLpQOb9S5/TVuWlH2fED/2H9E+PFKymiiuAjbdXcme8BeIHbbO9xXNZA7jo34uc6h1oK5wNGiRwSWw4qMf"
    "EbQfpsUYTMto1B6cFB0qXRYWFb4p5K1tXgWTGDdw7j0wr6u9sRKPur0j+UT2M2KE+sFdc8evTY4Wqj2FO9oA4Monvgz7SPed5iBJ"
    "In9ur3iftXyewsXN+/ixW0IfrU8f1GhyPx1YcY+oRnfMSHC/2gLfm9Vo9JCdOHMqkh6D3XG2dwkVxFcQwfaZXMD7ps60BXWwtLdy"
    "A6YXojZQodzuQQmxFBuG+bwNr9Gy7fqhaDhfpD62qNbL+lqyaX1YqGy6dozFsWf83127GMoLjSJMN7gjMaxMj5nFe79BzKWwODC5"
    "Q/lE9KnC1aqBwa0aWoOZhxnNCzsVxnyD0EngFuN0mWIOpaV/2uSKbl8AcE4xFjO+Tpcg/RkxXnv9+YAnQLmcjVRNqDDW3ZjNKOh7"
    "0ljSgb2MjOtXgq9kbo5MlrzOgwGU9MnL+7yXp36SVto43pQPuacDvfsPnizyi8nbR6DFQ1jz52tOtRXLiNB4LSKpnPAQQAuDF9c2"
    "cMzygrXSNvroaf2AJq6JTXgN0xu7oHP8DIZMqurzXBPg7sOqOhw5Y0Lbwko+0grRJYkz1XgOiIwFiie1KzyBkq7Gq6cHr6tMzCIK"
    "vkh+4A6KZ1mQvU1FKQLXdZzHTNeey13YW5PeFRZN89NlOsCeTO12e+ki+N/mti6DRNEuSGlELM+w8q3HengahyrBMaoCHz2y+Ab6"
    "BF0iFiBDsnU548uPkmwK/T30g5Eg9UOFZwhHMJl72Wg8Qo4nW/vYGIvD2CimxtnQq1l+tzLb6g5oauhyTvAqsQlU1ETgC1CZ0VQJ"
    "9iSx1c1nzrqJRhfnYeltmww5s8dRTwwvH4th1pmb80Uvz8UFIh1x8zWBUd5TIkcHrrOdUN104Vm9PQmbK4JsyrMQE0czEPiJUD2t"
    "FBrB+5RIM77XP3KeqSkrRZ6wsiru2PTF1iyl/lut22JUvspWdab8tKiZqIcLqNUedD4gVCJJ0/JQCqUb6APn/NOCPgkIeyDDxewa"
    "OGC5u28UxsPU8hPA6mZezIGt+PdK4Z3y8oDtclDIL+kY8ttezqwhL1544QHWqdqzfmNIWM/I01UBUX/bBSg7/pE6Fcg93o8Ltiky"
    "ogPUL0OSdcjduUSRVOXXquEZz46XoJ8JRjFfXorbmgVipJOYshQxx9HCTNiBgpHZisgFEx5UEwdii7U9uDMitW7m7UofzOS12hQH"
    "5NwNQ6awfpOuB6wKRGuaOAs7FxcqL5MMtvo0EWVvYHqHkb+slVotZY00qDt65mcbCdGnZaMbB+tDBG+7u0IDeCct/yF8b+getfyV"
    "1LFc+czNDG5hXmAv8MF6ifUN44+xNoIOZFPHeyGEoDMOr82n0/3DnlAYvDpnzRGfTtFqsBBFTiuqYrywZC9OpGAJO5NLqM+yW/Cl"
    "GykomnZLqsvT8GY="
)


def mode0(clear: str) -> str:
    return codec.encrypt_mode0(clear.encode("utf-8")).decode("ascii")


def mode1(clear: str) -> str:
    return codec.encrypt_special(clear.encode("utf-8")).decode("ascii")


def mode2(clear: str) -> str:
    return codec.encrypt_sensitive(clear.encode("utf-8"), iv=FIXED_IV).decode("ascii")


def build_catalog():
    """(raw envelope bytes, expected plaintext document)."""
    encrypted = {
        "Version": "159-test",
        "Servers": [{
            "Name": mode0("Test Server"),
            "Subname": mode0("Test Subname"),
            "ServerIPHost": mode1("test.invalid"),
            "OpenVPNTCPPort": mode0("443"),
            "OpenVPNSSLPort": mode0("443"),
            "flag": mode0("TEST"),
            "Username": mode2("synthetic-user"),
            "Password": mode2("synthetic-pass"),
            "CustomCert": "",  # Empty fields are plain "" in the live catalog, not mode-0 envelopes (mode0(b"") cannot round-trip: XXTEA needs >= 2 words).
            "Protocol": 0,
            "UDPMode": 0,
            "UdpAuthMode": 0,
            "UseCustomCert": False,
            "SlowDNS": {
                "NSNameServer": mode0("ns1.test.invalid"),
                "PubKey": mode0("0123456789abcdef" * 4),
            },
            "V2Ray": {
                "V2RayType": 0,
                "V2RayHost": mode1("v2.test.invalid"),
                "UUID": mode0("test-uuid-1234"),
                "PATH": mode1("/test"),
                "DNSMode": 0,
            },
        }],
        "Networks": [{
            "Name": mode0("Test Network"),
            "Info": mode0("Test info"),
            "TLSVersion": mode0("Default"),
            "SNIHost": mode1("sni.test.invalid"),
            "Payload": mode1("GET / HTTP/1.1"),
            "ServerProtocol": 0,
            "TunnelType": 3,
            "PayloadMode": 0,
            "AutoReplace": True,
            "OverrideTimeout": False,
            "EnableWS": False,
            "ProxySettings": {
                "Squid": mode0("[Default]"),
                "Port": mode0("8080"),
            },
            "UDPOptions": {
                "UpMbps": mode0("10"),
                "DlMbps": mode0("10"),
                "RecvConnectionWindow": mode0("65535"),
            },
            "V2Ray": {
                "UseCustomV2RAYConfig": False,
                "allowInsecure": False,
                "CustomV2RAYConfig": "",
                "SNIHost": mode1("ws.test.invalid"),
                "WSType": 0,
                "ReverseAddress": False,
                "ReverseOnly": False,
                "DNSMode": 0,
            },
        }],
        "Username": mode2("synthetic-top-user"),
        "Password": mode2("synthetic-top-pass"),
        "Notes": "synthetic",
    }
    expected = {
        "Version": "159-test",
        "Servers": [{
            "Name": "Test Server",
            "Subname": "Test Subname",
            "ServerIPHost": "test.invalid",
            "OpenVPNTCPPort": "443",
            "OpenVPNSSLPort": "443",
            "flag": "TEST",
            "Username": "synthetic-user",
            "Password": "synthetic-pass",
            "CustomCert": "",
            "Protocol": 0,
            "UDPMode": 0,
            "UdpAuthMode": 0,
            "UseCustomCert": False,
            "SlowDNS": {
                "NSNameServer": "ns1.test.invalid",
                "PubKey": "0123456789abcdef" * 4,
            },
            "V2Ray": {
                "V2RayType": 0,
                "V2RayHost": "v2.test.invalid",
                "UUID": "test-uuid-1234",
                "PATH": "/test",
                "DNSMode": 0,
            },
        }],
        "Networks": [{
            "Name": "Test Network",
            "Info": "Test info",
            "TLSVersion": "Default",
            "SNIHost": "sni.test.invalid",
            "Payload": "GET / HTTP/1.1",
            "ServerProtocol": 0,
            "TunnelType": 3,
            "PayloadMode": 0,
            "AutoReplace": True,
            "OverrideTimeout": False,
            "EnableWS": False,
            "ProxySettings": {
                "Squid": "[Default]",
                "Port": "8080",
            },
            "UDPOptions": {
                "UpMbps": "10",
                "DlMbps": "10",
                "RecvConnectionWindow": "65535",
            },
            "V2Ray": {
                "UseCustomV2RAYConfig": False,
                "allowInsecure": False,
                "CustomV2RAYConfig": "",
                "SNIHost": "ws.test.invalid",
                "WSType": 0,
                "ReverseAddress": False,
                "ReverseOnly": False,
                "DNSMode": 0,
            },
        }],
        "Username": "synthetic-top-user",
        "Password": "synthetic-top-pass",
        "Notes": "synthetic",
    }
    return codec.encrypt_mode0(
        json.dumps(encrypted, ensure_ascii=False).encode("utf-8")), expected


RAW, EXPECTED = build_catalog()


class PmTunnelLiteCatalogTests(unittest.TestCase):
    def test_known_answers_from_bundled_catalog(self):
        # Threefish-256 known answer, validated against the native
        # encryptor (libovpn3.so threefishEncrypt256, run under Unicorn).
        ct = codec.threefish256_encrypt_block(
            codec._hkdf32_key(), struct.pack("<2Q", 0, 0), bytes(32))
        self.assertEqual(ct.hex(), "9bdf65bebd3d645a3c02d03a353ec67f"
                                   "9c21086da64db0410ed7955c473466b4")
        self.assertEqual(codec.decrypt_mode0(
            "TeeRxfNsI6o5OljrZ+LN06A0YizD5mMSS+z6g+TmRY4O2Xpz3g2aJjZA7JcXpq6P"),
            b"Please update config first")
        self.assertEqual(codec.encrypt_mode0(
            b"Please update config first").decode(),
            "TeeRxfNsI6o5OljrZ+LN06A0YizD5mMSS+z6g+TmRY4O2Xpz3g2aJjZA7JcXpq6P")
        self.assertEqual(codec.decrypt_special(
            "+W/8xsYwLW01Mt0Yjwdg5LfoTsgTBGgUr9S2grqjS3E="), b"0.0.0.0")
        self.assertEqual(codec.encrypt_special(b"0.0.0.0").decode(),
                         "+W/8xsYwLW01Mt0Yjwdg5LfoTsgTBGgUr9S2grqjS3E=")
        self.assertEqual(codec.decrypt_sensitive(
            "EVkBv4pu7WQbY+EVDDKhc+v9qcoNuLvcs/wucmG7ljKvwofs"), b"qwfqeg")
        self.assertEqual(codec.decrypt_sensitive(
            "GSC3h3RsDkDFUwISTlqm46V+rUHNrLs7ZJBY+i3j0bHRQJ/P"), b"qwegqeg")

    def test_bundled_ejs_fallback_catalog(self):
        # res/ae/e.js: Version "1.0", 1 placeholder server, host 0.0.0.0.
        doc = codec.decode_catalog(EJS_B64.encode("ascii"))
        self.assertEqual(doc["Version"], "1.0")
        self.assertEqual(len(doc["Servers"]), 1)
        self.assertEqual(doc["Servers"][0]["ServerIPHost"], "0.0.0.0")
        self.assertEqual(doc["Servers"][0]["Name"], "Please update config first")
        self.assertEqual(json.loads(
            file_decoder.run(EJS_B64.encode("ascii")))["config"]["Version"], "1.0")

    def test_synthetic_catalog_codec_cli_and_isolated_worker(self):
        self.assertEqual(json.loads(catalog.run(RAW)), EXPECTED)
        result = decode_provider_catalog("pm-tunnel-lite", RAW)
        self.assertEqual(result["structuredJson"], EXPECTED)
        self.assertEqual(json.loads(result["rawText"]), EXPECTED)
        self.assertFalse(result["isPartial"])
        path = ROOT / "decoders/Python/apps/PM_Tunnel_Lite/server_catalog_decoder.py"
        proc = subprocess.run(
            [sys.executable, str(path), "--stdin"], input=RAW,
            cwd="/tmp", capture_output=True, check=True)
        self.assertEqual(json.loads(proc.stdout), EXPECTED)

    def test_redacted_decode_never_returns_credentials(self):
        redacted = codec.decode_catalog(RAW, redact=True)
        self.assertIsNone(redacted["Username"])
        self.assertIsNone(redacted["Password"])
        for srv in redacted["Servers"]:
            self.assertIsNone(srv["ServerIPHost"])
            self.assertIsNone(srv["Username"])
            self.assertIsNone(srv["Password"])
            self.assertIsNone(srv["CustomCert"])
        self.assertEqual(redacted["Servers"][0]["Name"], "Test Server")
        self.assertEqual(redacted["Networks"][0]["SNIHost"], "sni.test.invalid")

    def test_file_routes_js_custom_payload_and_link_prefix(self):
        # A .js catalog file opens through file_decoder.run.
        self.assertEqual(
            json.loads(file_decoder.run(RAW))["config"], EXPECTED)
        # custom_payload.json: a mode-0 JSON array of server entries.
        entry = {"Name": mode0("TEST SERVER"),
                 "ServerIPHost": mode1("0.0.0.0"),
                 "Protocol": 0, "isSetExpiry": False}
        payload = codec.encrypt_mode0(
            json.dumps([entry, entry]).encode("utf-8"))
        self.assertEqual(
            [file_decoder.dec_server_entry(dict(e)) for e in
             file_decoder.decode_custom_payload_text(payload.decode("ascii"))],
            [{"Name": "TEST SERVER", "ServerIPHost": "0.0.0.0",
              "Protocol": 0, "isSetExpiry": False}] * 2)
        self.assertEqual(
            json.loads(file_decoder.run(payload))["config"][0]["Name"],
            "TEST SERVER")
        # A file carrying the pmtunnellite:// prefix opens too.
        link = file_decoder.encode_link(entry)
        self.assertEqual(
            json.loads(file_decoder.run(link.encode("utf-8")))["config"]["Name"],
            "TEST SERVER")
        with self.assertRaises(codec.DecodeError):
            file_decoder.run(b"AAAAAAAAAAAAAAAAAAAAAA==")
        with self.assertRaises(codec.DecodeError):
            file_decoder.run(b"")

    def test_text_link_round_trip(self):
        # Adapted from the deliverable pmtunnel_files.py round-trip:
        # the pmtunnellite:// scheme opens through the explicit dispatch
        # in file_decoder.decode_text and end to end through
        # text_bridge.dispatch; a file carrying the scheme prefix opens
        # through file_decoder.run; garbage / a wrong scheme prefix /
        # a wrong-profile envelope are None. No real link observed yet.
        entry = {"Name": mode0("TEST SERVER"),
                 "ServerIPHost": mode1("0.0.0.0"),
                 "Protocol": 0, "isSetExpiry": False}
        link = file_decoder.encode_link(entry)
        parsed = json.loads(file_decoder.decode_text(link))
        self.assertEqual(parsed["application"], "PM Tunnel Lite")
        self.assertEqual(parsed["protocol"], "pmtunnellite://")
        self.assertEqual(parsed["config"]["Name"], "TEST SERVER")
        self.assertEqual(parsed["config"]["ServerIPHost"], "0.0.0.0")
        self.assertEqual(json.loads(text_dispatch(link)), parsed)
        self.assertEqual(
            json.loads(file_decoder.decode_text("PMTUNNELLITE://" + link[len("pmtunnellite://"):]))["config"],
            parsed["config"])
        self.assertEqual(json.loads(text_dispatch("PMTUNNELLITE://" + link[len("pmtunnellite://"):]))["config"],
                         parsed["config"])
        self.assertEqual(
            json.loads(file_decoder.run(link.encode("utf-8")))["config"],
            parsed["config"])
        for bad in ("pmtunnellite://AAAAAAAAAAAAAAAAAAAAAA==",
                    "pmtunnel:// " + link[len("pmtunnellite://"):],
                    "pmtunnellite://aGVsbG8gd29ybGQ="):
            with self.subTest(bad=bad[:22]):
                self.assertIsNone(file_decoder.decode_text(bad))
                self.assertIsNone(text_dispatch(bad))
        self.assertIsNone(file_decoder.decode_text("pmtunnellite://"))
        self.assertIsNone(file_decoder.decode_text(""))

    def test_drlb_diagnostic_only(self):
        # The bundled drlb fixture (dossier tests/fixtures/drlb.bin)
        # decrypts to a DEX v037 (4,976 B) via pmtunnel_files.py
        # --self-test; it is NOT a user format and decode_drlb is
        # diagnostic only. Here: garbage is rejected, never a DEX.
        with self.assertRaises(codec.DecodeError):
            file_decoder.decode_drlb(b"not a dex resource at all....")
        with self.assertRaises(codec.DecodeError):
            file_decoder.decode_drlb(bytes(64))

    def test_corruption_rejects_entire_catalog(self):
        no_servers = dict(json.loads(json.dumps(EXPECTED)))
        del no_servers["Servers"]
        for invalid in (b"", b"<html/>", RAW[:-5],
                        codec.encrypt_mode0(json.dumps(no_servers).encode("utf-8"))):
            with self.subTest(length=len(invalid)):
                with self.assertRaises(codec.DecodeError):
                    catalog.run(invalid)
        with self.assertRaises(codec.DecodeError):
            catalog._NoRedirect().redirect_request(None, None, None, None, None, None)


if __name__ == "__main__":
    unittest.main()
