"""HX catalog and .hxt readers: independent Java fixtures and standalone CLI."""
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import Request

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "decoders/Python/apps/HX_Tunnel_VPN"
FIXTURE = json.loads((ROOT / "tests/golden/hx_tunnel_vectors.json").read_text("utf-8"))


def load(name):
    spec = importlib.util.spec_from_file_location(name, APP / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


catalog = load("HX_Tunnel_VPN")
profiles = load("HX_Tunnel_VPN_archivos")


class HXTunnelTests(unittest.TestCase):
    def test_independent_java_catalog_preserves_every_list_and_field(self):
        result = catalog.decode(FIXTURE["catalog"])
        self.assertEqual(result, FIXTURE["expectedCatalog"])
        self.assertEqual(json.loads(catalog.run(FIXTURE["catalog"])), result)
        for field in catalog.LIST_FIELDS:
            self.assertEqual(len(result[field]), 1)
        self.assertEqual(result["Password"], "fixture-only")
        self.assertEqual(result["future"], {"keep": True})

    def test_independent_java_profile_keeps_policies_and_embedded_text(self):
        result = profiles.decode(FIXTURE["profile"])
        self.assertEqual(result, FIXTURE["expectedProfile"])
        self.assertEqual(json.loads(profiles.run(FIXTURE["profile"])), result)
        self.assertEqual(result["payload"], "GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n")
        self.assertEqual(result["message"], "First\nSecond\r\nThird")
        self.assertEqual(result["tweak_password"], "fixture-only")
        self.assertEqual(result["tweak_expiry"], "2000-01-01-00-00")
        self.assertEqual(result["hwid_lock"], "SYNTHETIC-DEVICE")
        self.assertEqual(result["block_rooted"], "true")
        self.assertIsInstance(result["embedded"], str)
        self.assertEqual(json.loads(result["embedded"])["host"], "example.invalid")

    def test_jni_modified_utf8_supplementary_characters_and_null(self):
        self.assertEqual(profiles.decode(FIXTURE["profile"])["friendly_name"], "Prueba 日本 Perú 𝄞")
        self.assertEqual(profiles._modified_utf8(b"a\xc0\x80b"), "a\0b")
        self.assertEqual(profiles._modified_utf8(b"\xed\xa0\xb4\xed\xb4\x9e"), "𝄞")
        for raw in [b"\xff", b"\xed\xa0\x80", "𝄞".encode("utf-8")]:
            with self.assertRaises(profiles.DecodeError):
                profiles._modified_utf8(raw)

    def test_java_length_word_rounds_and_all_padding_remainders(self):
        for vector in FIXTURE["lengthVectors"]:
            self.assertEqual(catalog.decode(vector["data"]), vector["expected"])
        self.assertEqual({v["utf8Bytes"] % 4 for v in FIXTURE["lengthVectors"]}, {0, 1, 2, 3})

    def test_modified_delta_and_shared_keys_are_required(self):
        with patch.object(catalog, "DELTA", 0x9e3779b9):
            self.assertIsNone(catalog.run(FIXTURE["catalog"]))
        with patch.object(catalog, "CATALOG_KEY", b"foreign-format"):
            self.assertIsNone(catalog.run(FIXTURE["catalog"]))
        with patch.object(profiles, "PROFILE_KEY", b"foreign-format"):
            self.assertIsNone(profiles.run(FIXTURE["profile"]))

    def test_original_icon_name_dimensions_and_checksum(self):
        data = (APP / "HX_Tunnel_VPN.png").read_bytes()
        self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(struct.unpack(">II", data[16:24]), (512, 512))
        self.assertEqual(hashlib.sha256(data).hexdigest(), "7af9ffe33fdfbf66598d3713440f09d56effd5b6f9d1d81bec67a470f15773ef")

    def test_engines_are_exclusive(self):
        self.assertIsNone(catalog.run(FIXTURE["profile"]))
        self.assertIsNone(profiles.run(FIXTURE["catalog"]))
        self.assertFalse(hasattr(profiles, "fetch_catalog"))

    def test_transport_bom_base64_wrapping_and_missing_padding(self):
        data = FIXTURE["catalog"]
        for value in ["\ufeff \r\n" + data + "\n", data.rstrip("="),
                      "\r\n".join(data[i:i+76] for i in range(0, len(data), 76))]:
            self.assertEqual(catalog.decode(value), FIXTURE["expectedCatalog"])

    def test_hex_uppercase_bom_and_whitespace(self):
        data = FIXTURE["profile"]
        for value in [data.upper(), "\ufeff " + data + "\n",
                      " \r\n".join(data[i:i+64] for i in range(0, len(data), 64))]:
            self.assertEqual(profiles.decode(value), FIXTURE["expectedProfile"])

    def test_invalid_input_types_unicode_and_resource_sizes(self):
        for module in [catalog, profiles]:
            for value in [None, 1, [], b"", b"\xff", b"A", b"!bad!", "\ud800"]:
                self.assertIsNone(module.run(value))
            with patch.object(module, "MAX_BYTES", 8):
                self.assertIsNone(module.run(b"x" * 9))
                self.assertIsNone(module.run("日" * 3))

    def test_noncanonical_or_truncated_hex_and_raw_json(self):
        for value in ["0", "0x00", "ab:cd", "gg", FIXTURE["profile"][:-1],
                      '{"friendly_name":"clear"}', "hxt://abcd"]:
            self.assertIsNone(profiles.run(value))

    def test_truncated_words_and_invalid_internal_catalog_length(self):
        for raw in [b"a", b"abcd", b"abcde", bytes(8), bytes(12)]:
            self.assertIsNone(catalog.run(base64.b64encode(raw)))
        raw = base64.b64decode(FIXTURE["catalog"])
        self.assertIsNone(catalog.run(base64.b64encode(raw[:-1])))
        self.assertIsNone(catalog.run(b"AAAA==="))

    def test_strict_json_negative_independent_java_vectors(self):
        for vector in FIXTURE["invalidVectors"]:
            self.assertIsNone(catalog.run(vector["catalog"]))
            self.assertIsNone(profiles.run(vector["profile"]))

    def test_catalog_schema_preserves_unknown_fields_and_requires_object_lists(self):
        self.assertEqual(catalog._catalog_json('{"Free_servers":[],"future":true}'),
                         {"Free_servers": [], "future": True})
        for text in ['{}', '[]', '{"Payloads":null}', '{"Free_servers":[{},1]}', '{"Vip_servers":{}}']:
            with self.assertRaises(catalog.DecodeError):
                catalog._catalog_json(text)

    def test_thousand_servers_and_two_thousand_payloads_not_truncated(self):
        doc = {field: [{"id": i, "future": None} for i in range(1000)] for field in catalog.LIST_FIELDS}
        doc["Payloads"] = [{"id": i} for i in range(2000)]
        self.assertEqual(catalog._catalog_json(json.dumps(doc)), doc)

    def test_json_depth_and_node_limits(self):
        for module in [catalog, profiles]:
            with patch.object(module, "MAX_DEPTH", 2):
                with self.assertRaises(module.DecodeError):
                    module._json('{"a":{"b":{"c":1}}}')
            with patch.object(module, "MAX_NODES", 4):
                with self.assertRaises(module.DecodeError):
                    module._json('{"a":1,"b":2}')
            with self.assertRaises(module.DecodeError):
                module._json("[" * 1500 + "0" + "]" * 1500)

    def test_offline_api_never_downloads(self):
        with patch.object(catalog, "build_opener", side_effect=AssertionError("unexpected network")):
            self.assertIsNotNone(catalog.run(FIXTURE["catalog"]))
            self.assertIsNone(catalog.run("invalid"))
            self.assertIsNotNone(profiles.run(FIXTURE["profile"]))

    def test_http_get_original_url_headers_timeout_and_read_limit(self):
        with patch.object(catalog, "build_opener") as build:
            response = build.return_value.open.return_value.__enter__.return_value
            response.status = 200
            response.read.return_value = FIXTURE["catalog"].encode()
            self.assertEqual(catalog.decode(catalog.fetch_catalog()), FIXTURE["expectedCatalog"])
            req = build.return_value.open.call_args.args[0]
            self.assertEqual(req.full_url, catalog.CATALOG_URL)
            self.assertEqual(req.get_method(), "GET")
            self.assertIsNone(req.data)
            self.assertEqual(req.get_header("User-agent"), catalog.USER_AGENT)
            self.assertEqual(build.return_value.open.call_args.kwargs, {"timeout": 20})
            response.read.assert_called_once_with(catalog.MAX_BYTES + 1)

    def test_https_prechecks_and_redirect_policy(self):
        with patch.object(catalog, "build_opener", side_effect=AssertionError("unexpected request")):
            for url in ["http://example.invalid", "https://u:p@example.invalid", "https:///missing", "https://example.invalid/#fragment"]:
                with self.assertRaises(catalog.DecodeError):
                    catalog.fetch_catalog(url)
        req = Request(catalog.CATALOG_URL)
        handler = catalog._HTTPSRedirect()
        for url in ["http://example.invalid", "https://u:p@example.invalid", "https://example.invalid/#fragment"]:
            self.assertIsNone(handler.redirect_request(req, None, 302, "", {}, url))
        self.assertEqual(handler.redirect_request(req, None, 302, "", {}, "https://example.invalid").full_url, "https://example.invalid")
        self.assertEqual(handler.max_redirections, 5)

    def test_http_failures_are_sanitized_and_bounded(self):
        for error, code in [(HTTPError(catalog.CATALOG_URL, 403, "private-value", {}, None), "ACCESS_DENIED"),
                            (URLError("private-value"), "DOWNLOAD_FAILED")]:
            with patch.object(catalog, "build_opener") as build:
                build.return_value.open.side_effect = error
                with self.assertRaises(catalog.DecodeError) as ctx:
                    catalog.fetch_catalog()
            self.assertEqual(ctx.exception.code, code)
            self.assertNotIn("private-value", str(ctx.exception))
        with patch.object(catalog, "MAX_BYTES", 8), patch.object(catalog, "build_opener") as build:
            response = build.return_value.open.return_value.__enter__.return_value
            response.status = 200
            response.read.return_value = b"x" * 9
            with self.assertRaises(catalog.DecodeError) as ctx:
                catalog.fetch_catalog()
            self.assertEqual(ctx.exception.code, "SIZE_LIMIT")

    def test_standalone_scripts_can_be_copied_separately(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for filename, name in [("HX_Tunnel_VPN.py", "catalog"), ("HX_Tunnel_VPN_archivos.py", "profile")]:
                script = root / filename
                shutil.copyfile(APP / filename, script)
                source, out = root / (name + ".txt"), root / (name + ".json")
                source.write_text(FIXTURE[name])
                proc = subprocess.run([sys.executable, str(script), str(source), "-o", str(out)], cwd=root, capture_output=True, text=True)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(json.loads(out.read_text()), FIXTURE["expectedCatalog" if name == "catalog" else "expectedProfile"])
                script.unlink()

    def test_cli_encrypted_text_and_explicit_catalog_download(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(profiles.main(["--text", FIXTURE["profile"]]), 0)
        self.assertEqual(json.loads(out.getvalue()), FIXTURE["expectedProfile"])
        with patch.object(catalog, "fetch_catalog", return_value=FIXTURE["catalog"]) as fetch, contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(catalog.main(["--url"]), 0)
        fetch.assert_called_once_with(catalog.CATALOG_URL)
        self.assertEqual(json.loads(out.getvalue()), FIXTURE["expectedCatalog"])

    def test_cli_failures_preserve_output_and_missing_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, out = root / "bad.txt", root / "out.json"
            source.write_text("!broken!")
            out.write_text("keep previous")
            for module in [catalog, profiles]:
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(module.main([str(source), "-o", str(out)]), 1)
                self.assertIn("error", json.loads(err.getvalue()))
                self.assertEqual(out.read_text(), "keep previous")
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(module.main([str(root / "missing")]), 2)


if __name__ == "__main__":
    unittest.main()
