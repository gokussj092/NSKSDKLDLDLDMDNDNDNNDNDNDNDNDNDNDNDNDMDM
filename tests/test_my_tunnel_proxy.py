"""Original-native golden vectors contain synthetic .invalid hosts only."""
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

from decoders.Python.apps.My_Tunnel_Proxy import codec, file_decoder, server_catalog_decoder as catalog

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads((ROOT / "tests/golden/my_tunnel_proxy_vectors.json").read_text("utf-8"))


class MyTunnelProxyTests(unittest.TestCase):
    def test_original_native_vectors_for_all_three_layers(self):
        for name, method in (("mainVectors", codec.decrypt_main),
                             ("specialVectors", codec.decrypt_special),
                             ("sensitiveVectors", codec.decrypt_sensitive)):
            for vector in VECTORS[name]:
                with self.subTest(kind=name, length=len(vector["plain"])):
                    self.assertEqual(method(vector["cipher"]), vector["plain"])

    def test_profile_preserves_complete_json_and_expiry_pin_flags(self):
        result = json.loads(file_decoder.run(VECTORS["profile"].encode()))
        self.assertEqual(result, VECTORS["expectedProfile"])
        self.assertEqual(result["Expiry"], 1)
        self.assertTrue(result["Lock"])
        self.assertEqual(result["Unknown"]["keep"], [False, None, 2.5, "dGVzdA=="])

    def test_catalog_preserves_complete_json_without_network(self):
        with patch.object(catalog, "download", side_effect=AssertionError("network")):
            result = catalog.run(VECTORS["catalog"].encode())
        self.assertEqual(json.loads(result), VECTORS["expectedCatalog"])

    def test_bom_wrapped_base64_and_missing_base64_padding(self):
        raw = VECTORS["catalog"]
        wrapped = b"\xef\xbb\xbf\r\n" + b"\r\n".join(raw[i:i+60].encode() for i in range(0, len(raw), 60))
        self.assertEqual(json.loads(catalog.run(wrapped)), VECTORS["expectedCatalog"])
        self.assertEqual(json.loads(catalog.run(raw.rstrip("=").encode())), VECTORS["expectedCatalog"])

    def test_ciphertext_zero_is_preserved_before_threefish_padding(self):
        vector = next(v for v in VECTORS["specialVectors"] if v["plain"] == VECTORS["zeroCiphertextSNI"])
        self.assertEqual(codec.decrypt_special(vector["cipher"]), VECTORS["zeroCiphertextSNI"])

    def test_cloud_pointer_is_identified_without_claiming_profile_download(self):
        self.assertEqual(codec.cloud_reference(VECTORS["cloudReference"].encode()), {
            "kind": "cloud_reference", "reference": "12345678.cfg", "profileDownloaded": False,
        })
        with self.assertRaises(codec.DecodeError):
            file_decoder.run(VECTORS["cloudReference"].encode())

    def test_wrong_document_invalid_json_and_corrupt_fields_fail_closed(self):
        for data in VECTORS["invalidCatalogs"]:
            with self.subTest(kind="catalog", length=len(data)), self.assertRaises(codec.DecodeError):
                catalog.run(data.encode())
        for data in VECTORS["invalidProfiles"]:
            with self.subTest(kind="profile", length=len(data)), self.assertRaises(codec.DecodeError):
                file_decoder.run(data.encode())
        with self.assertRaises(codec.DecodeError):
            catalog.run(VECTORS["profile"].encode())

    def test_size_depth_non_utf8_and_crypto_block_limits(self):
        for data in (b"", b"\xff", b"x" * (codec.MAX_BYTES + 1), b"%%%%", b"https://example.invalid"):
            with self.subTest(size=len(data)), self.assertRaises(codec.DecodeError):
                catalog.run(data)
        deep = []
        for _ in range(codec.MAX_DEPTH + 2):
            deep = [deep]
        with self.assertRaises(codec.DecodeError):
            codec._walk(deep)
        for method, bad in ((codec.decrypt_main, "YQ=="),
                            (codec.decrypt_special, "YQ=="),
                            (codec.decrypt_sensitive, "\u200c"),
                            (codec.decrypt_sensitive, "normal text")):
            with self.assertRaises(codec.DecodeError):
                method(bad)

    def test_cli_runs_from_outside_repository_and_sanitizes_errors(self):
        folder = ROOT / "decoders/Python/apps/My_Tunnel_Proxy"
        with tempfile.TemporaryDirectory() as temp:
            for name, payload, expected in (
                ("file_decoder.py", VECTORS["profile"], VECTORS["expectedProfile"]),
                ("server_catalog_decoder.py", VECTORS["catalog"], VECTORS["expectedCatalog"]),
            ):
                source = Path(temp) / "sample"
                source.write_text(payload, encoding="utf-8")
                result = subprocess.run([sys.executable, str(folder / name), str(source)],
                                        cwd=temp, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(json.loads(result.stdout), expected)
            bad = subprocess.run([sys.executable, str(folder / "file_decoder.py")], input=b"secret-input",
                                 cwd=temp, capture_output=True, timeout=10)
            self.assertEqual(bad.returncode, 1)
            self.assertEqual(bad.stdout, b"")
            self.assertNotIn(b"secret-input", bad.stderr)

    def test_download_uses_only_fixed_url_and_bounded_response(self):
        class Response:
            status = 200
            headers = {}
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, amount):
                assert amount == codec.MAX_BYTES + 1
                return VECTORS["catalog"].encode()
        class Opener:
            def open(self, request, timeout):
                assert request.full_url == catalog.CATALOG_URL
                assert timeout == 25
                assert request.get_header("User-agent") == "My Tunnel Proxy/2.3"
                return Response()
        with patch.object(catalog, "build_opener", return_value=Opener()):
            self.assertEqual(catalog.download(), VECTORS["catalog"].encode())
        with patch.object(catalog, "build_opener", side_effect=OSError("private error detail")):
            with self.assertRaisesRegex(codec.DecodeError, "catálogo autorizado"):
                catalog.download()
        with self.assertRaises(codec.DecodeError):
            catalog._NoRedirect().redirect_request(None, None, 302, "", {}, "https://example.invalid/")

    def test_manifest_matches_original_icon_and_fixed_engine(self):
        folder = ROOT / "decoders/Python/apps/My_Tunnel_Proxy"
        manifest = json.loads((folder / "manifest.json").read_text())
        self.assertEqual(manifest["id"], "my-tunnel-proxy")
        self.assertEqual(manifest["compatibleVersions"], ["2.3"])
        icon = (folder / manifest["icon"]["file"]).read_bytes()
        self.assertEqual(hashlib.sha256(icon).hexdigest(), manifest["icon"]["sha256"])
        self.assertEqual(icon, (ROOT / "cloud/web/public/server-vpn-icons/my-tunnel-proxy.png").read_bytes())


class MyTunnelCloudParityTests(unittest.TestCase):
    def test_full_json_crosses_all_isolated_worker_routes(self):
        sys.path.insert(0, str(ROOT / "cloud/workers/python"))
        from engine import decode_file, decode_text, decode_provider_catalog
        cases = (
            (decode_file("mtp", VECTORS["profile"].encode()), VECTORS["expectedProfile"]),
            (decode_text(VECTORS["profile"]), VECTORS["expectedProfile"]),
            (decode_provider_catalog("my-tunnel-proxy", VECTORS["catalog"].encode()), VECTORS["expectedCatalog"]),
        )
        for result, expected in cases:
            self.assertFalse(result["isPartial"])
            self.assertEqual(result["structuredJson"], expected)
            self.assertEqual(json.loads(result["rawText"]), expected)


if __name__ == "__main__":
    unittest.main()
