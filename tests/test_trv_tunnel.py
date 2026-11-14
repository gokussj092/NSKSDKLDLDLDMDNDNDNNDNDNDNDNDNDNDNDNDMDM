"""Fresh TRV APK Java/native golden vectors; no real accounts or CI network."""
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

from decoders.Python.apps.TRV_TUNNEL import file_decoder as files
from decoders.Python.apps.TRV_TUNNEL import server_catalog_decoder as catalogs

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "decoders/Python/apps/TRV_TUNNEL"
SHARED = ROOT / "decoders/Python/apps/HX_Tunnel_VPN"


def golden():
    return json.loads((ROOT / "tests/golden/trv_tunnel_vectors.json").read_text("utf-8"))


class TRVTunnelTests(unittest.TestCase):
    def test_original_java_xxtea_vectors_and_custom_delta_match_shared_codec(self):
        for item in golden()["primitiveVectors"]:
            with self.subTest(length=len(item["plain"])):
                result = catalogs._codec.decrypt_catalog_bytes(item["cipherBase64"])
                self.assertEqual(result.decode(), item["plain"])
        self.assertEqual(catalogs._codec.DELTA, (-1638454863) & 0xffffffff)

    def test_native_profile_vectors_preserve_complete_json_modified_utf8_and_locks(self):
        for fixture in golden()["profiles"]:
            with self.subTest(name=fixture["expected"]["friendly_name"]):
                result = json.loads(files.run(fixture["data"].encode()))
                self.assertEqual(result, fixture["expected"])
                self.assertIsInstance(result["sslws"], str)
                self.assertIsInstance(result["block_rooted"], str)
                self.assertEqual(result["Unknown"]["keep"], [None, True, False, 17, 2.5, "literal", "dGVzdA=="])
        result = json.loads(files.run(golden()["profiles"][0]["data"].encode()))
        self.assertEqual(result["tweak_password"], "fake-pin")
        self.assertEqual(result["hwid_lock"], "synthetic-hwid")
        self.assertIn("😀", result["friendly_name"])

    def test_catalog_retains_all_lists_credentials_unknowns_and_payload_types(self):
        fixture = golden()
        with patch.object(catalogs, "download", side_effect=AssertionError("network")):
            result = json.loads(catalogs.run(fixture["catalog"].encode()))
        self.assertEqual(result, fixture["expectedCatalog"])
        self.assertEqual(set(catalogs.LIST_FIELDS) & result.keys(), set(catalogs.LIST_FIELDS))
        self.assertEqual(result["Free_servers"][0]["password"], "fake-password")
        self.assertIsInstance(result["Payloads"][0]["sslws"], str)
        self.assertEqual(result["Unknown"]["server_host"], "literal")

    def test_bom_wrapping_unpadded_base64_uppercase_hex_and_whitespace(self):
        fixture = golden()
        data = fixture["catalog"]
        for value in ("\ufeff\r\n" + data, data.rstrip("="), "\r\n".join(data[i:i+60] for i in range(0, len(data), 60))):
            self.assertEqual(json.loads(catalogs.run(value.encode())), fixture["expectedCatalog"])
        data = fixture["profiles"][0]["data"]
        for value in (data.upper(), "\ufeff\r\n" + data, "\r\n".join(data[i:i+64] for i in range(0, len(data), 64))):
            self.assertEqual(json.loads(files.run(value.encode())), fixture["profiles"][0]["expected"])

    def test_original_encrypted_invalid_documents_fail_without_partial_results(self):
        fixture = golden()
        for run, samples, error in ((files.run, fixture["invalidProfiles"], files.DecodeError),
                                    (catalogs.run, fixture["invalidCatalogs"], catalogs.DecodeError)):
            for sample in samples:
                with self.subTest(module=run.__module__, length=len(sample)), self.assertRaises(error):
                    run(sample.encode())

    def test_limits_wrong_formats_cloud_links_and_nonbytes_are_rejected(self):
        for run, error in ((files.run, files.DecodeError), (catalogs.run, catalogs.DecodeError)):
            for data in (None, "not bytes", b"", b"\xff", b"@bad@", b"0", b"hxt://abcd", b"https://example.invalid",
                         b"<html>private</html>", b"x" * (files.MAX_BYTES + 1)):
                with self.subTest(module=run.__module__), self.assertRaises(error):
                    run(data)
        with self.assertRaises(files.DecodeError): files.run(golden()["catalog"].encode())
        with self.assertRaises(catalogs.DecodeError): catalogs.run(golden()["profiles"][0]["data"].encode())
        with self.assertRaises(files.DecodeError): files.run(golden()["profiles"][0]["data"][:-1].encode())

    def test_download_folder_runs_with_stdlib_only_without_apk_or_repository(self):
        fixture = golden()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for filename in ("file_decoder.py", "server_catalog_decoder.py"):
                shutil.copy2(APP / filename, root / filename)
            shutil.copy2(SHARED / "HX_Tunnel_VPN_archivos.py", root / "hxt_file_codec.py")
            shutil.copy2(SHARED / "HX_Tunnel_VPN.py", root / "hxt_catalog_codec.py")
            for filename, data, expected, stdin_args in (
                ("file_decoder.py", fixture["profiles"][0]["data"], fixture["profiles"][0]["expected"], []),
                ("server_catalog_decoder.py", fixture["catalog"], fixture["expectedCatalog"], ["--stdin"]),
            ):
                sample = root / "input.cipher"
                sample.write_text(data)
                for arguments, stdin in (([str(sample)], None), (stdin_args, data.encode())):
                    result = subprocess.run([sys.executable, "-S", str(root / filename), *arguments], input=stdin,
                                            cwd=root, capture_output=True, timeout=15)
                    self.assertEqual(result.returncode, 0, result.stderr.decode())
                    self.assertEqual(json.loads(result.stdout), expected)
                result = subprocess.run([sys.executable, "-S", str(root / filename), *stdin_args],
                                        input=b"private-input", cwd=root, capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b"")
                self.assertNotIn(b"private-input", result.stderr)

    def test_fixed_download_is_bounded_and_rejects_html_http_compression_and_redirects(self):
        class Response:
            status = 200
            headers = {}
            def __init__(self, data): self.data = data
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size):
                self.read_limit = size
                return self.data[:size]
        with patch.object(catalogs, "build_opener") as factory:
            response = Response(golden()["catalog"].encode())
            factory.return_value.open.return_value = response
            self.assertEqual(catalogs.download(), response.data)
            args, kwargs = factory.return_value.open.call_args
            self.assertEqual(args[0].full_url, catalogs.CATALOG_URL)
            self.assertEqual(args[0].headers["User-agent"], "TRV TUNNEL/2.4")
            self.assertEqual(kwargs["timeout"], 25)
            self.assertEqual(response.read_limit, catalogs.MAX_BYTES + 1)
            for data in (b"", b"x" * (catalogs.MAX_BYTES + 1), b"\r\n<html>Site Unavailable</html>"):
                factory.return_value.open.return_value = Response(data)
                with self.assertRaises(catalogs.DecodeError): catalogs.download()
            factory.return_value.open.return_value = response
            response.headers = {"Content-Encoding": "gzip"}
            with self.assertRaises(catalogs.DecodeError): catalogs.download()
            response.headers = {}
            response.status = 503
            with self.assertRaises(catalogs.DecodeError): catalogs.download()
            factory.return_value.open.side_effect = OSError("private remote exception")
            with self.assertRaisesRegex(catalogs.DecodeError, "No se pudo descargar"):
                catalogs.download()
        with self.assertRaises(catalogs.DecodeError):
            catalogs._NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.invalid")

    def test_correct_original_icon_and_unchanged_shared_sources_match_manifest(self):
        manifest = json.loads((APP / "manifest.json").read_text())
        icon = (APP / "TRV_TUNNEL.png").read_bytes()
        self.assertEqual(hashlib.sha256(icon).hexdigest(), "cca027b2a1a69d1cb0a70b77ea902175f93ddf9c405bdbcaf196a0135770526e")
        self.assertLess(len(icon), 256 * 1024 + 1)
        self.assertEqual(icon, (ROOT / "cloud/web/public/server-vpn-icons/trv-tunnel.png").read_bytes())
        for item in manifest["sharedCodecs"]:
            self.assertEqual(hashlib.sha256((ROOT / item["source"]).read_bytes()).hexdigest(), item["sha256"])
        self.assertEqual(manifest["files"]["extensions"], ["hxt"])
        self.assertFalse(manifest["files"]["exporterCertified"])

    def test_actual_cloud_catalog_and_shared_hxt_route_preserve_complete_json(self):
        from cloud.workers.python.engine import decode_file, decode_provider_catalog, load_runtime_file_engines, DecodeFailure
        fixture = golden()
        for profile in fixture["profiles"]:
            result = decode_file("hxt", profile["data"].encode())
            self.assertEqual(result["structuredJson"], profile["expected"])
            self.assertEqual(json.loads(result["rawText"]), profile["expected"])
            self.assertFalse(result["isPartial"])
            self.assertFalse(result["decoder"]["exporterCertified"])
        result = decode_provider_catalog("trv-tunnel", fixture["catalog"].encode())
        self.assertEqual(result["structuredJson"], fixture["expectedCatalog"])
        self.assertFalse(result["isPartial"])
        self.assertEqual(len(load_runtime_file_engines()), 267)
        self.assertIn("/HX_Tunnel_VPN/HX_Tunnel_VPN_archivos.py", load_runtime_file_engines()["hxt"]["source"])
        with self.assertRaises(DecodeFailure): decode_provider_catalog("trv-tunnel", fixture["invalidCatalogs"][0].encode())


if __name__ == "__main__":
    unittest.main()
