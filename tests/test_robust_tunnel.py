"""Independent original-Java vectors; no real accounts or remote calls in CI."""
from __future__ import annotations
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from decoders.Python.apps.Robust_Tunnel_VPN import server_catalog_decoder as decoder

ROOT = Path(__file__).resolve().parents[1]


def golden():
    return json.loads((ROOT / "tests/golden/robust_tunnel_vectors.json").read_text("utf-8"))


class RobustTunnelTests(unittest.TestCase):
    def test_original_java_primitive_vectors_include_utf8_and_key_normalization(self):
        for item in golden()["primitiveVectors"]:
            with self.subTest(length=len(item["plain"]), key=item["keyHex"]):
                self.assertEqual(decoder.decrypt_xxtea(base64.b64decode(item["cipherBase64"]),
                                                     bytes.fromhex(item["keyHex"])).decode(), item["plain"])

    def test_complete_catalog_matches_original_java_and_preserves_types(self):
        fixture = golden()
        with patch.object(decoder, "download", side_effect=AssertionError("network")):
            result = json.loads(decoder.run(fixture["catalog"].encode()))
        self.assertEqual(result, fixture["expected"])
        self.assertEqual(result["Unknown"]["keep"], [None, True, False, 1, 2.5, "CA", "DE", "dGVzdA=="])
        self.assertIsInstance(result["ConfigVersion"], float)
        self.assertEqual(result["Servers"][0]["ServerFlag"], "DE")
        self.assertEqual(result["Tweaks"][0]["TweakIcon"], "DE")

    def test_nested_fields_and_configuration_strings_are_not_reinterpreted(self):
        fixture = golden()
        result = decoder.decode(fixture["catalog"].encode())
        self.assertEqual(result["Tweaks"][0]["SSHSettings"]["HTTPPayload"],
                         fixture["expected"]["Tweaks"][0]["SSHSettings"]["HTTPPayload"])
        self.assertIsInstance(result["Tweaks"][1]["UDPHSettings"]["UDPConf"], str)
        self.assertEqual(result["Certs"], fixture["expected"]["Certs"])
        self.assertEqual(decoder.decrypt_field(""), "")

    def test_bom_line_breaks_and_android_unpadded_base64(self):
        fixture = golden()
        value = fixture["catalog"]
        data = b"\xef\xbb\xbf\r\n" + b"\r\n".join(value[i:i+60].encode() for i in range(0, len(value), 60))
        self.assertEqual(decoder.decode(data), fixture["expected"])
        self.assertEqual(decoder.decode(value.rstrip("=").encode()), fixture["expected"])

    def test_malformed_json_wrong_schema_and_corrupt_field_fail_closed(self):
        for value in golden()["invalidCatalogs"]:
            with self.subTest(length=len(value)), self.assertRaises(decoder.DecodeError):
                decoder.run(value.encode())

    def test_size_depth_unicode_and_block_limits(self):
        for value in (b"", b"\xff", b"%%%%", b"https://example.invalid/catalog", b"x" * (decoder.MAX_BYTES + 1)):
            with self.subTest(length=len(value)), self.assertRaises(decoder.DecodeError):
                decoder.run(value)
        for value in (b"a", b"1234", b"123456789"):
            with self.assertRaises(decoder.DecodeError):
                decoder.decrypt_xxtea(value, decoder.CATALOG_KEY)
        for value in ("odd", "00", "not hexadecimal"):
            with self.assertRaises(decoder.DecodeError):
                decoder.decrypt_field(value)
        data = []
        for _ in range(decoder.MAX_DEPTH + 2):
            data = [data]
        with self.assertRaises(decoder.DecodeError):
            decoder._walk(data)

    def test_cli_file_and_stdin_work_without_repository_imports_or_site_packages(self):
        script = ROOT / "decoders/Python/apps/Robust_Tunnel_VPN/server_catalog_decoder.py"
        fixture = golden()
        with tempfile.TemporaryDirectory() as temp:
            copy = Path(temp) / "Robust_Tunnel_VPN.py"
            copy.write_bytes(script.read_bytes())
            data = Path(temp) / "catalog-copy"
            data.write_text(fixture["catalog"])
            for arguments, stdin in (([str(data)], None), (["--stdin"], fixture["catalog"].encode())):
                result = subprocess.run([sys.executable, "-S", str(copy), *arguments], input=stdin,
                                        cwd=temp, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(json.loads(result.stdout), fixture["expected"])
            result = subprocess.run([sys.executable, "-S", str(copy), "--stdin"], input=b"private-input",
                                    cwd=temp, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b"")
            self.assertNotIn(b"private-input", result.stderr)

    def test_download_is_fixed_bounded_and_has_no_login_parameters(self):
        fixture = golden()
        class Response:
            status = 200
            headers = {}
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, amount):
                assert amount == decoder.MAX_BYTES + 1
                return fixture["catalog"].encode()
        class Opener:
            def open(self, request, timeout):
                assert request.full_url == decoder.CATALOG_URL
                assert "username" not in request.full_url and "device_id" not in request.full_url
                assert request.get_header("User-agent") == "Robust Tunnel VPN/isvsoft 16.4.7"
                assert timeout == 25
                return Response()
        with patch.object(decoder, "build_opener", return_value=Opener()):
            self.assertEqual(decoder.download(), fixture["catalog"].encode())
        with patch.object(decoder, "build_opener", side_effect=OSError("private network detail")):
            with self.assertRaisesRegex(decoder.DecodeError, "catálogo autorizado"):
                decoder.download()
        with self.assertRaises(decoder.DecodeError):
            decoder._NoRedirect().redirect_request(None, None, 302, "", {}, "https://example.invalid/")

    def test_download_rejects_bad_status_compression_empty_and_oversized_response(self):
        class Response:
            status = 200
            headers = {}
            payload = b"test"
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, amount): return self.payload
        for status, headers, payload in ((500, {}, b"x"), (200, {"Content-Encoding": "gzip"}, b"x"),
                                         (200, {}, b""), (200, {}, b"x" * (decoder.MAX_BYTES + 1))):
            response = Response()
            response.status, response.headers, response.payload = status, headers, payload
            with patch.object(decoder, "build_opener") as opener:
                opener.return_value.open.return_value = response
                with self.assertRaises(decoder.DecodeError):
                    decoder.download()

    def test_manifest_and_original_png_match_public_icon(self):
        folder = ROOT / "decoders/Python/apps/Robust_Tunnel_VPN"
        manifest = json.loads((folder / "manifest.json").read_text())
        self.assertEqual(manifest["id"], "robust-tunnel")
        self.assertEqual(manifest["compatibleVersions"], ["isvsoft 16.4.7"])
        raw = (folder / manifest["icon"]["file"]).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), manifest["icon"]["sha256"])
        self.assertEqual(raw, (ROOT / "cloud/web/public/server-vpn-icons/robust-tunnel.png").read_bytes())
        self.assertEqual(manifest["files"]["profileExportIdentified"], False)
        self.assertFalse((folder / "file_decoder.py").exists())


class RobustCloudParityTests(unittest.TestCase):
    def test_entire_json_crosses_real_offline_worker_subprocess(self):
        sys.path.insert(0, str(ROOT / "cloud/workers/python"))
        from engine import decode_provider_catalog, DecodeFailure
        fixture = golden()
        result = decode_provider_catalog("robust-tunnel", fixture["catalog"].encode())
        self.assertFalse(result["isPartial"])
        self.assertEqual(result["structuredJson"], fixture["expected"])
        self.assertEqual(json.loads(result["rawText"]), fixture["expected"])
        with self.assertRaises(DecodeFailure) as failure:
            decode_provider_catalog("robust-tunnel", b"wrong ciphertext")
        self.assertEqual(failure.exception.code, "DECODE_FAILED")


if __name__ == "__main__":
    unittest.main()
