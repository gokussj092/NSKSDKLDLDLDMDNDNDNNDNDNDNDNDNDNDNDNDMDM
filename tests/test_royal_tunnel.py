"""Royal 7.0: independent native/JCE golden vectors, no real accounts or network."""
from __future__ import annotations
import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from decoders.Python.apps.Royal_Tunnel_VPN import codec
from decoders.Python.apps.Royal_Tunnel_VPN import file_decoder as files
from decoders.Python.apps.Royal_Tunnel_VPN import server_catalog_decoder as catalogs

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "decoders/Python/apps/Royal_Tunnel_VPN"


def golden():
    return json.loads((ROOT / "tests/golden/royal_tunnel_vectors.json").read_text("utf-8"))


class RoyalTunnelTests(unittest.TestCase):
    def test_original_native_framing_matches_independent_java_jce_vectors(self):
        for item in golden()["nativeVectors"]:
            with self.subTest(mode=item["mode"], length=len(item["plain"])):
                if item["mode"] == 0:
                    self.assertEqual(codec.decrypt_gcm(item["cipherBase64"]), item["plain"])
                else:
                    raw = base64.b64decode(item["cipherBase64"])
                    result = unpad(AES.new(codec.NATIVE_KEY, AES.MODE_CBC, iv=raw[:16]).decrypt(raw[16:]), 16)
                    self.assertEqual(result.decode(), item["plain"])

    def test_all_exported_profile_modes_preserve_complete_json_and_server_string(self):
        with patch.object(catalogs, "download", side_effect=AssertionError("network")):
            for fixture in golden()["profiles"]:
                with self.subTest(tunnelType=fixture["tunnelType"]):
                    result = json.loads(files.run(fixture["data"].encode()))
                    self.assertEqual(result, fixture["expected"])
                    self.assertIsInstance(result["Server"], str)
                    self.assertEqual(result["MyPass"], "fake-pin")
                    self.assertTrue(result["RootBlock"])
                    self.assertEqual(result["ExpireDate"], 1)
                    if result["Server"]:
                        server = json.loads(result["Server"])
                        self.assertEqual(server["Username"], "fake-user")
                        self.assertEqual(server["Unknown"]["Name"], "leave literal")

    def test_full_catalog_including_tweaks_and_nested_protocols_matches_java(self):
        fixture = golden()
        result = json.loads(catalogs.run(fixture["catalog"].encode()))
        self.assertEqual(result, fixture["expectedCatalog"])
        self.assertEqual(result["Tweaks"][0]["Flag"], "CA")
        self.assertEqual(result["Servers"][0]["Flag"], "DE")
        self.assertEqual(result["Tweaks"][0]["Unknown"]["Payload"], "no automatic recursion")
        self.assertIsInstance(result["Tweaks"][0]["v2rayjson"], str)
        self.assertEqual(result["Unknown"]["keep"], [None, False, 42, 1.5, "DE", "dGVzdA=="])

    def test_bom_android_wrapped_and_unpadded_base64(self):
        fixture = golden()
        for run, text, expected in ((files.run, fixture["profiles"][0]["data"], fixture["profiles"][0]["expected"]),
                                    (catalogs.run, fixture["catalog"], fixture["expectedCatalog"])):
            wrapped = b"\xef\xbb\xbf\r\n" + b"\r\n".join(text[i:i+60].encode() for i in range(0, len(text), 60))
            self.assertEqual(json.loads(run(wrapped)), expected)
            self.assertEqual(json.loads(run(text.rstrip("=").encode())), expected)

    def test_wrong_brand_old_version_gcm_damage_and_invalid_nested_server_fail_closed(self):
        for data in golden()["invalidProfiles"]:
            with self.subTest(length=len(data)), self.assertRaises(codec.DecodeError):
                files.run(data.encode())

    def test_invalid_catalog_fields_json_duplicates_depth_numbers_and_utf8_fail_closed(self):
        for data in golden()["invalidCatalogs"]:
            with self.subTest(length=len(data)), self.assertRaises(codec.DecodeError):
                catalogs.run(data.encode())

    def test_profile_and_catalog_are_distinct_formats_and_cloud_links_are_not_files(self):
        fixture = golden()
        for run, data in ((files.run, fixture["catalog"].encode()),
                          (catalogs.run, fixture["profiles"][0]["data"].encode()),
                          (files.run, b"Roy://example-reference")):
            with self.assertRaises(codec.DecodeError):
                run(data)

    def test_limits_truncated_blocks_invalid_encoding_and_nonbytes(self):
        for run in (files.run, catalogs.run):
            for data in (b"", b"\xff", b"@@@@", b"https://example.invalid", b"<html>private</html>",
                         b"x" * (codec.MAX_BYTES + 1), None, "not bytes"):
                with self.subTest(run=run.__module__, length=len(data) if data else 0), self.assertRaises(codec.DecodeError):
                    run(data)
        for raw in (b"a", b"1234", b"123456789"):
            with self.assertRaises(codec.DecodeError):
                codec.decrypt_xxtea(raw)
        for value in ("@@@", "YQ=="):
            with self.assertRaises(codec.DecodeError):
                codec.decrypt_gcm(value)
        for value in (codec.decrypt_gcm, codec.decrypt_cfb, codec.decrypt_tweak):
            self.assertEqual(value(""), "")

    def test_both_clis_from_isolated_copy_without_repository_imports(self):
        fixture = golden()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for filename in ("codec.py", "file_decoder.py", "server_catalog_decoder.py"):
                shutil.copy2(APP / filename, root / filename)
            for filename, data, expected, stdinargs in (
                ("file_decoder.py", fixture["profiles"][0]["data"], fixture["profiles"][0]["expected"], []),
                ("server_catalog_decoder.py", fixture["catalog"], fixture["expectedCatalog"], ["--stdin"]),
            ):
                sample = root / "synthetic.input"
                sample.write_text(data)
                for arguments, stdin in (([str(sample)], None), (stdinargs, data.encode())):
                    result = subprocess.run([sys.executable, str(root / filename), *arguments], input=stdin,
                                            cwd=root, capture_output=True, timeout=15)
                    self.assertEqual(result.returncode, 0, result.stderr.decode())
                    self.assertEqual(json.loads(result.stdout), expected)
                result = subprocess.run([sys.executable, str(root / filename), *stdinargs],
                                        input=b"private-input", cwd=root, capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b"")
                self.assertNotIn(b"private-input", result.stderr)

    def test_fixed_download_no_arbitrary_url_and_unavailable_site_is_reported(self):
        class Response:
            status = 200
            headers = {}
            def __init__(self, data): self.data = data
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, length):
                self.limit = length
                return self.data[:length]
        sample = golden()["catalog"].encode()
        with patch.object(catalogs, "build_opener") as factory:
            response = Response(sample)
            factory.return_value.open.return_value = response
            self.assertEqual(catalogs.download(), sample)
            args, kwargs = factory.return_value.open.call_args
            self.assertEqual(args[0].full_url, catalogs.CATALOG_URL)
            self.assertEqual(kwargs["timeout"], 25)
            self.assertEqual(response.limit, codec.MAX_BYTES + 1)
            for data in (b"", b"x" * (codec.MAX_BYTES + 1), b"<html>Site Unavailable</html>"):
                factory.return_value.open.return_value = Response(data)
                with self.assertRaises(codec.DecodeError):
                    catalogs.download()
            response = Response(sample)
            response.headers = {"Content-Encoding": "gzip"}
            factory.return_value.open.return_value = response
            with self.assertRaises(codec.DecodeError): catalogs.download()
            response.headers = {}
            response.status = 503
            with self.assertRaises(codec.DecodeError): catalogs.download()
            factory.return_value.open.side_effect = OSError("private remote error")
            with self.assertRaisesRegex(codec.DecodeError, "No se pudo descargar"):
                catalogs.download()
        with self.assertRaises(codec.DecodeError):
            catalogs._NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.invalid")

    def test_original_correct_royal_icon_is_preserved_and_public_card_is_visible(self):
        data = (APP / "Royal_Tunnel_VPN.png").read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), "d5b0acadb3759da52c90cd45a671e264ed98b58e5c838d496e6999b5e1198309")
        self.assertGreater(len(data), 256 * 1024)
        manifest = json.loads((APP / "manifest.json").read_text())
        self.assertTrue(manifest["catalog"]["publicRegistrationEnabled"])
        self.assertFalse(manifest["catalog"]["publicDecodeEnabled"])
        self.assertNotIn('"royal-tunnel"', (ROOT / "cloud/web/lib/server-vpn-provider.mjs").read_text())
        self.assertIn('"royal-tunnel"', (ROOT / "cloud/web/lib/server-vpn-catalog.mjs").read_text())

    def test_actual_cloud_subprocess_preserves_complete_profile_and_catalog(self):
        sys.path.insert(0, str(ROOT / "cloud/workers/python"))
        from engine import decode_file, decode_provider_catalog, DecodeFailure
        fixture = golden()
        for profile in fixture["profiles"]:
            result = decode_file("roy", profile["data"].encode())
            self.assertEqual(result["structuredJson"], profile["expected"])
            self.assertEqual(json.loads(result["rawText"]), profile["expected"])
            self.assertFalse(result["isPartial"])
            self.assertFalse(result["decoder"]["exporterCertified"])
        result = decode_provider_catalog("royal-tunnel", fixture["catalog"].encode())
        self.assertEqual(result["structuredJson"], fixture["expectedCatalog"])
        self.assertFalse(result["isPartial"])
        for call, value in ((lambda data: decode_file("roy", data), fixture["invalidProfiles"][0]),
                            (lambda data: decode_provider_catalog("royal-tunnel", data), fixture["invalidCatalogs"][0])):
            with self.assertRaises(DecodeFailure): call(value.encode())

    def test_cloud_dispatch_preserves_legacy_by_distinct_alphabet_without_modern_fallback(self):
        from cloud.workers.python import engine
        from tests.golden.a23_generators import SYNTHETIC_GENERATORS
        legacy = SYNTHETIC_GENERATORS["batch7-roy"]()
        self.assertTrue(engine._is_legacy_roy(legacy))
        self.assertFalse(engine._is_legacy_roy(b""))
        self.assertFalse(engine._is_legacy_roy(b"\xff"))
        self.assertFalse(engine._is_legacy_roy(golden()["profiles"][0]["data"].encode()))
        result = engine.decode_file("roy", legacy)
        self.assertEqual(result["rawText"], (ROOT / "tests/golden/expected/batch7-roy.txt").read_text())
        self.assertNotEqual(result["decoder"]["phase"], "C8")
        # A modern bad-tag envelope must fail at its new codec, not retry C0.
        bad = golden()["invalidProfiles"][3].encode()
        # Pin the registry first: loading it legitimately reads C0.
        routes = engine.load_runtime_file_engines()
        with patch.object(engine, "load_runtime_file_engines", return_value=routes), \
                patch.object(engine, "load_file_engines", side_effect=AssertionError("legacy fallback")):
            with self.assertRaises(engine.DecodeFailure): engine.decode_file("roy", bad)


if __name__ == "__main__":
    unittest.main()
