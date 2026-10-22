"""APK-derived Java fixtures; no live catalogs, accounts or CI provider fetches."""
from __future__ import annotations

import base64
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

from decoders.Python.apps.AustroPlus_VPN import codec, file_decoder as files, server_catalog_decoder as catalog

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "decoders/Python/apps/AustroPlus_VPN"
V = json.loads((ROOT / "tests/golden/austroplus_vectors.json").read_text("utf-8"))


class AustroPlusTests(unittest.TestCase):
    def test_original_java_xxtea_vectors_match_unchanged_shared_primitive(self):
        for vector in V["xxteaVectors"]:
            self.assertEqual(codec.ec._decrypt_xxtea(base64.b64decode(vector["cipherBase64"]), codec.CATALOG_KEY).decode(), vector["plain"])
        self.assertEqual(codec.ec.DELTA, 0x9e3779b9)

    def test_original_java_xor_and_android_wrapped_double_base64_vectors(self):
        for vector in V["fieldVectors"]:
            self.assertEqual(codec.xor_field(vector["xor"]), vector["plain"])
            self.assertEqual(codec.double_base64(vector["doubleBase64"]), vector["plain"])
        self.assertIn("\n", V["fieldVectors"][-1]["doubleBase64"])

    def test_complete_profiles_preserve_types_flags_password_unicode_and_server_string(self):
        for fixture in V["profiles"]:
            result = json.loads(files.run(fixture["data"].encode()))
            self.assertEqual(result, fixture["expected"])
            self.assertIsInstance(result["CONFIG"]["Server"], str)
            self.assertEqual(result["CONFIG"]["Unknown"]["Password"], "literal")
        config = V["profiles"][0]["expected"]["CONFIG"]
        self.assertEqual(config["MyPass"], "fake-pass")
        self.assertTrue(config["isHdwIdLock"])
        self.assertEqual(json.loads(config["Server"])["Password"], "fake-password")
        self.assertEqual(json.loads(files.run(V["profiles"][1]["data"].encode()))["CONFIG"]["Payload"], "")

    def test_complete_catalog_keeps_unknowns_and_never_follows_its_update_url(self):
        with patch.object(catalog, "download", side_effect=AssertionError("network")):
            result = json.loads(catalog.run(V["catalog"].encode()))
        self.assertEqual(result, V["expectedCatalog"])
        self.assertEqual(result["url_updater"], "https://example.invalid/catalog")
        self.assertEqual(result["Tweaks"][0]["Unknown"]["Payload"], "literal")

    def test_gcm_rejects_nonce_ciphertext_tag_tampering_and_truncation(self):
        raw = base64.b64decode(V["profiles"][0]["data"])
        for index in (0, 12, len(raw) - 1):
            damaged = bytearray(raw); damaged[index] ^= 1
            with self.subTest(index=index), self.assertRaises(codec.DecodeError):
                files.run(base64.b64encode(damaged))
        for size in (1, 12, 27, len(raw) - 1):
            with self.assertRaises(codec.DecodeError): files.run(base64.b64encode(raw[:size]))

    def test_bom_whitespace_wrapping_and_unpadded_input(self):
        for run, data, expected in ((files.run, V["profiles"][0]["data"], V["profiles"][0]["expected"]),
                                    (catalog.run, V["catalog"], V["expectedCatalog"])):
            for text in ("\ufeff\r\n" + data, data.rstrip("="), "\r\n".join(data[i:i+60] for i in range(0, len(data), 60))):
                self.assertEqual(json.loads(run(text.encode())), expected)

    def test_authenticated_invalid_documents_and_corrupt_fields_fail_closed(self):
        for run, key in ((files.run, "invalidProfiles"), (catalog.run, "invalidCatalogs")):
            for data in V[key]:
                with self.subTest(group=key, size=len(data)), self.assertRaises(codec.DecodeError): run(data.encode())
        with self.assertRaises(codec.DecodeError): files.run(V["catalog"].encode())
        with self.assertRaises(codec.DecodeError): catalog.run(V["profiles"][0]["data"].encode())

    def test_limits_invalid_bytes_urls_and_html_are_rejected(self):
        for run, limit in ((files.run, codec.MAX_PROFILE_BYTES), (catalog.run, codec.MAX_BYTES)):
            for data in (None, "not bytes", b"", b"\xff", b"%%%%", b"https://example.invalid", b"<html>private</html>", b"x" * (limit + 1)):
                with self.subTest(module=run.__module__), self.assertRaises(codec.DecodeError): run(data)

    def test_downloader_fixes_url_and_enforces_status_size_encoding_redirect_rules(self):
        class Response:
            status = 200
            headers = {}
            def __init__(self, data): self.data = data
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size): self.limit = size; return self.data[:size]
        with patch.object(catalog, "build_opener") as factory:
            response = Response(V["catalog"].encode()); factory.return_value.open.return_value = response
            self.assertEqual(catalog.download(), response.data)
            args, kwargs = factory.return_value.open.call_args
            self.assertEqual(args[0].full_url, catalog.CATALOG_URL)
            self.assertEqual(args[0].get_header("User-agent"), "AustroPlus VPN/13.0.1")
            self.assertEqual(kwargs["timeout"], 25); self.assertEqual(response.limit, codec.MAX_BYTES + 1)
            for data in (b"", b"\r\n<html>Unavailable</html>", b"x" * (codec.MAX_BYTES + 1)):
                factory.return_value.open.return_value = Response(data)
                with self.assertRaises(codec.DecodeError): catalog.download()
            for status, headers in ((503, {}), (200, {"Content-Encoding": "gzip"})):
                response.status, response.headers = status, headers; factory.return_value.open.return_value = response
                with self.assertRaises(codec.DecodeError): catalog.download()
            factory.return_value.open.side_effect = OSError("private details")
            with self.assertRaisesRegex(codec.DecodeError, "catálogo autorizado"): catalog.download()
        with self.assertRaises(codec.DecodeError):
            catalog._NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.invalid")

    def test_actual_bundle_runs_without_repo_and_catalog_needs_no_site_packages(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder); env = dict(os.environ); env.pop("PYTHONPATH", None)
            for name in ("codec.py", "file_decoder.py", "server_catalog_decoder.py"):
                shutil.copy2(APP / name, path / name)
            shutil.copy2(ROOT / "decoders/Python/ec.py", path / "ec.py")
            for script, payload, expected, stdin_flags, python_flags in (
                ("file_decoder.py", V["profiles"][0]["data"], V["profiles"][0]["expected"], [], []),
                ("server_catalog_decoder.py", V["catalog"], V["expectedCatalog"], ["--stdin"], ["-S"]),
            ):
                source = path / "input.cipher"; source.write_text(payload)
                for flags, stdin in (([str(source)], None), (stdin_flags, payload.encode())):
                    result = subprocess.run([sys.executable, *python_flags, str(path / script), *flags], input=stdin,
                                            cwd=path, env=env, capture_output=True, timeout=15)
                    self.assertEqual(result.returncode, 0, result.stderr.decode()); self.assertEqual(json.loads(result.stdout), expected)
                bad = subprocess.run([sys.executable, *python_flags, str(path / script), *stdin_flags], input=b"private-input",
                                     cwd=path, env=env, capture_output=True, timeout=15)
                self.assertEqual(bad.returncode, 1); self.assertEqual(bad.stdout, b""); self.assertNotIn(b"private-input", bad.stderr)

    def test_original_icon_and_shared_source_match_manifest_exactly(self):
        manifest = json.loads((APP / "manifest.json").read_text()); icon = (APP / "AustroPlus_VPN.png").read_bytes()
        self.assertEqual(hashlib.sha256(icon).hexdigest(), manifest["icon"]["sha256"])
        self.assertEqual(icon, (ROOT / "cloud/web/public/server-vpn-icons/austroplus-vpn.png").read_bytes())
        self.assertEqual(manifest["compatibleVersions"], ["13.0.1"]); self.assertFalse(manifest["files"]["exporterCertified"])
        shared = manifest["sharedPrimitive"]
        self.assertEqual(hashlib.sha256((ROOT / shared["source"]).read_bytes()).hexdigest(), shared["sha256"])

    @unittest.skipUnless(shutil.which("java"), "Java optional source oracle not installed")
    def test_original_java_oracle_independently_confirms_frozen_cryptographic_vectors(self):
        commands = [("xxd", base64.b64decode(x["cipherBase64"]), x["plain"]) for x in V["xxteaVectors"]]
        commands += [(kind, x[field].encode(), x["plain"]) for x in V["fieldVectors"] for kind, field in (("xor", "xor"), ("double", "doubleBase64"))]
        commands += [("gcmd", x["data"].encode(), codec.decrypt_profile(x["data"])) for x in V["profiles"]]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "commands.tsv"
            path.write_text("\n".join(kind + "\t" + base64.b64encode(data).decode() for kind, data, _ in commands))
            result = subprocess.run(["java", str(ROOT / "tests/golden/austroplus_oracle.java"), str(path)], capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual([base64.b64decode(line).decode() for line in result.stdout.decode().splitlines()], [expected for _, _, expected in commands])


class AustroPlusCloudTests(unittest.TestCase):
    def test_complete_profiles_and_catalog_cross_actual_isolated_worker_boundary(self):
        from cloud.workers.python.engine import decode_file, decode_provider_catalog, DecodeFailure
        for fixture in V["profiles"]:
            result = decode_file("aro", fixture["data"].encode())
            self.assertEqual(result["structuredJson"], fixture["expected"]); self.assertFalse(result["isPartial"])
        result = decode_provider_catalog("austroplus-vpn", V["catalog"].encode())
        self.assertEqual(result["structuredJson"], V["expectedCatalog"]); self.assertFalse(result["isPartial"])
        damaged = bytearray(base64.b64decode(V["profiles"][0]["data"])); damaged[-1] ^= 1
        with self.assertRaises(DecodeFailure): decode_file("aro", base64.b64encode(damaged))

    def test_historical_aro_keeps_frozen_result_and_runtime_inventory(self):
        from cloud.workers.python.engine import decode_file, load_runtime_file_engines, load_file_engines
        from tests.golden.a23_batch3 import aro_json_bytes
        result = decode_file("aro", aro_json_bytes())
        self.assertEqual(result["rawText"], (ROOT / "tests/golden/expected/aro-minus18.txt").read_text())
        self.assertEqual(len(load_file_engines()), 240); self.assertEqual(len(load_runtime_file_engines()), 247)
        self.assertTrue(load_file_engines()["aro"]["source"].endswith("/aro.py"))
        self.assertTrue(load_runtime_file_engines()["aro"]["source"].endswith("/AustroPlus_VPN/file_decoder.py"))


if __name__ == "__main__":
    unittest.main()
