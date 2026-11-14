"""AC 1.4: native-generated fake fixtures and complete Cloud boundary parity."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from decoders.Python.apps.AC_TUNNEL_VPN import codec, file_decoder as files, server_catalog_decoder as catalog

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "decoders/Python/apps/AC_TUNNEL_VPN"
V = json.loads((ROOT / "tests/golden/ac_tunnel_vpn_vectors.json").read_text("utf-8"))


class AcTunnelVpnTests(unittest.TestCase):
    def test_original_native_vectors_cover_three_types_and_multiple_blocks(self):
        for name, method in (("mainVectors", codec.decrypt_main),
                             ("specialVectors", codec.decrypt_special),
                             ("sensitiveVectors", codec.decrypt_sensitive)):
            for vector in V[name]:
                with self.subTest(kind=name, size=len(vector["plain"])):
                    self.assertEqual(method(vector["cipher"]), vector["plain"])

    def test_full_profile_unicode_nested_formats_and_import_flags_survive(self):
        result = json.loads(files.run(V["profile"].encode()))
        self.assertEqual(result, V["expectedProfile"])
        self.assertTrue(result["Lock"])
        self.assertTrue(result["isPinEnabled"])
        self.assertEqual(result["NetworkPinCode"], "0000")
        self.assertIsInstance(result["V2Ray"]["CustomV2RAYConfig"], str)
        self.assertEqual(result["Unknown"]["Password"], "literal password")
        self.assertEqual(result["Unknown"]["Name"], "literal name")

    def test_catalog_complete_json_and_plain_metadata_never_use_network(self):
        with patch.object(catalog, "download", side_effect=AssertionError("network")):
            result = json.loads(catalog.run(V["catalog"].encode()))
        self.assertEqual(result, V["expectedCatalog"])
        self.assertEqual(result["Version"], "synthetic-1.4")
        self.assertEqual(result["Unknown"]["Name"], "literal name")

    def test_genuine_aes_ciphertext_zero_is_not_mistaken_for_threefish_fill(self):
        vector = next(x for x in V["specialVectors"] if x["plain"] == V["zeroCiphertextSNI"])
        self.assertEqual(codec.decrypt_special(vector["cipher"]), V["zeroCiphertextSNI"])

    def test_bom_wrapped_base64_and_unpadded_input(self):
        data = V["catalog"]
        for text in ("\ufeff\r\n" + data, data.rstrip("="),
                     "\r\n".join(data[i:i+60] for i in range(0, len(data), 60))):
            self.assertEqual(json.loads(catalog.run(text.encode())), V["expectedCatalog"])
        self.assertEqual(json.loads(files.run(("\ufeff\r\n" + V["profile"]).encode())), V["expectedProfile"])

    def test_cloud_reference_is_only_a_pointer_and_never_a_decoded_profile(self):
        self.assertEqual(codec.cloud_reference(V["cloudReference"].encode()), {
            "kind": "cloud_reference", "reference": "12345678.cfg", "profileDownloaded": False,
        })
        with self.assertRaises(codec.DecodeError):
            files.run(V["cloudReference"].encode())
        with self.assertRaises(codec.DecodeError):
            codec.cloud_reference(V["profile"].encode())

    def test_original_native_encrypted_invalid_documents_fail_without_partial_json(self):
        for run, group in ((catalog.run, "invalidCatalogs"), (files.run, "invalidProfiles")):
            for data in V[group]:
                with self.subTest(kind=group, size=len(data)), self.assertRaises(codec.DecodeError):
                    run(data.encode())
        with self.assertRaises(codec.DecodeError): catalog.run(V["profile"].encode())
        with self.assertRaises(codec.DecodeError): files.run(V["catalog"].encode())

    def test_limits_non_utf8_wrong_crypto_and_urls_are_rejected(self):
        for run in (files.run, catalog.run):
            for data in (None, "not bytes", b"", b"\xff", b"x" * (codec.MAX_BYTES + 1),
                         b"%%%", b"https://example.invalid", b"<html>private</html>"):
                with self.subTest(module=run.__module__), self.assertRaises(codec.DecodeError): run(data)
        for method in (codec.decrypt_main, codec.decrypt_special, codec.decrypt_sensitive):
            with self.assertRaises(codec.DecodeError): method("YQ==")
        with self.assertRaises(codec.DecodeError): codec.decrypt_sensitive("\u200c\u200d")

    def test_download_has_fixed_url_limits_no_redirects_and_sanitized_failures(self):
        class Response:
            status = 200
            headers = {}
            def __init__(self, data): self.data = data
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, amount):
                self.limit = amount
                return self.data[:amount]
        with patch.object(catalog, "build_opener") as factory:
            response = Response(V["catalog"].encode())
            factory.return_value.open.return_value = response
            self.assertEqual(catalog.download(), response.data)
            args, kwargs = factory.return_value.open.call_args
            self.assertEqual(args[0].full_url, catalog.CATALOG_URL)
            self.assertEqual(args[0].get_header("User-agent"), "AC TUNNEL VPN/1.4")
            self.assertEqual(kwargs["timeout"], 25)
            self.assertEqual(response.limit, codec.MAX_BYTES + 1)
            for data in (b"", b"\r\n<html>Site Unavailable</html>", b"x" * (codec.MAX_BYTES + 1)):
                factory.return_value.open.return_value = Response(data)
                with self.assertRaises(codec.DecodeError): catalog.download()
            for status, headers in ((503, {}), (200, {"Content-Encoding": "gzip"})):
                response.status, response.headers = status, headers
                factory.return_value.open.return_value = response
                with self.assertRaises(codec.DecodeError): catalog.download()
            factory.return_value.open.side_effect = OSError("private provider details")
            with self.assertRaisesRegex(codec.DecodeError, "catálogo autorizado"): catalog.download()
        with self.assertRaises(codec.DecodeError):
            catalog._NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.invalid")

    def test_bundled_scripts_work_outside_repository_with_exact_shared_primitive(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            environment = dict(os.environ)
            environment.pop("PYTHONPATH", None)
            for name in ("codec.py", "file_decoder.py", "server_catalog_decoder.py"):
                shutil.copy2(APP / name, path / name)
            shutil.copy2(ROOT / "decoders/Python/renz.py", path / "renz.py")
            for script, data, expected, stdin_args in (
                ("file_decoder.py", V["profile"], V["expectedProfile"], []),
                ("server_catalog_decoder.py", V["catalog"], V["expectedCatalog"], ["--stdin"]),
                ("file_decoder.py", V["cloudReference"], {"kind": "cloud_reference", "reference": "12345678.cfg", "profileDownloaded": False}, ["--reference"]),
            ):
                source = path / "input.cipher"
                source.write_text(data)
                file_args = [str(source), *(["--reference"] if "--reference" in stdin_args else [])]
                for arguments, stdin in ((file_args, None), (stdin_args, data.encode())):
                    result = subprocess.run([sys.executable, str(path / script), *arguments], input=stdin,
                                            cwd=path, env=environment, capture_output=True, timeout=15)
                    self.assertEqual(result.returncode, 0, result.stderr.decode())
                    self.assertEqual(json.loads(result.stdout), expected)
                bad = subprocess.run([sys.executable, str(path / script), *stdin_args], input=b"private-input",
                                     cwd=path, env=environment, capture_output=True, timeout=15)
                self.assertEqual(bad.returncode, 1)
                self.assertEqual(bad.stdout, b"")
                self.assertNotIn(b"private-input", bad.stderr)

    def test_original_icon_and_manifest_match_without_changing_shared_engine(self):
        manifest = json.loads((APP / "manifest.json").read_text())
        icon = (APP / "AC_TUNNEL_VPN.png").read_bytes()
        self.assertEqual(hashlib.sha256(icon).hexdigest(), manifest["icon"]["sha256"])
        self.assertEqual(icon, (ROOT / "cloud/web/public/server-vpn-icons/ac-tunnel-vpn.png").read_bytes())
        self.assertEqual(manifest["compatibleVersions"], ["1.4"])
        self.assertFalse(manifest["files"]["exporterCertified"])
        self.assertEqual(hashlib.sha256((ROOT / "decoders/Python/renz.py").read_bytes()).hexdigest(), manifest["sharedPrimitiveSha256"])


class AcTunnelCloudTests(unittest.TestCase):
    def test_complete_native_fixture_through_all_real_subprocess_routes(self):
        from cloud.workers.python.engine import decode_file, decode_text, decode_provider_catalog
        for result, expected in (
            (decode_file("actun", V["profile"].encode()), V["expectedProfile"]),
            (decode_text(V["profile"]), V["expectedProfile"]),
            (decode_text(V["profile"].replace("actunnelvpn://", "ACTUNNELVPN://", 1)), V["expectedProfile"]),
            (decode_provider_catalog("ac-tunnel-vpn", V["catalog"].encode()), V["expectedCatalog"]),
        ):
            self.assertEqual(result["structuredJson"], expected)
            self.assertEqual(json.loads(result["rawText"]), expected)
            self.assertFalse(result["isPartial"])
        from cloud.workers.python.engine import DecodeFailure
        with self.assertRaises(DecodeFailure): decode_text(V["invalidProfiles"][2])

    def test_historical_raw_file_and_generic_text_keep_their_original_result(self):
        from tests.test_renz_family import profile_fixture
        from decoders.Python import renz
        from cloud.workers.python.engine import decode_file, decode_text, load_runtime_file_engines, load_file_engines
        document = {"Server": "example.invalid", "Port": 443, "Enabled": False, "Notes": "Prueba 日本語"}
        raw = profile_fixture("actunnelvpn", document)
        self.assertEqual(decode_file("actun", raw)["structuredJson"], json.loads(renz.decode_file(raw, ".actun")))
        link = "actunnelvpn://" + raw.decode()
        self.assertEqual(decode_text(link)["structuredJson"], json.loads(renz.decode_text(link)))
        self.assertEqual(decode_file("actunnelvpn", raw)["structuredJson"], json.loads(renz.decode_file(raw, ".actunnelvpn")))
        self.assertEqual(len(load_runtime_file_engines()), 270)
        self.assertEqual(len(load_file_engines()), 240)
        self.assertEqual(load_runtime_file_engines()["actunnelvpn"], load_file_engines()["actunnelvpn"])


if __name__ == "__main__":
    unittest.main()
