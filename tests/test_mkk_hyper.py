"""MKK catalog authentication, mkk:// CBC and complete subscription reports."""
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
APP = ROOT / "decoders/Python/apps/MKK_Hyper_VPN"
FIXTURE = json.loads((ROOT / "tests/golden/mkk_hyper_vectors.json").read_text("utf-8"))


def load(name):
    spec = importlib.util.spec_from_file_location(name, APP / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


catalog = load("MKK_Hyper_VPN")
texts = load("MKK_Hyper_VPN_textos")


class MKKHyperTests(unittest.TestCase):
    def test_independent_jce_catalog_complete_fields(self):
        self.assertEqual(catalog.decode(FIXTURE["catalog"]), FIXTURE["expectedCatalog"])
        self.assertEqual(json.loads(catalog.run(FIXTURE["catalog"])), FIXTURE["expectedCatalog"])
        self.assertTrue(catalog.decode(FIXTURE["catalog"])["servers"][0]["vip"])

    def test_appended_gcm_tag_independent_vector(self):
        self.assertEqual(catalog.decode(FIXTURE["appendedCatalog"]), FIXTURE["expectedCatalog"])
        envelope = json.loads(FIXTURE["appendedCatalog"])
        envelope["mac"] = None
        self.assertEqual(catalog.decode(json.dumps(envelope)), FIXTURE["expectedCatalog"])

    def test_authentication_fails_for_nonce_cipher_and_tag_changes(self):
        for field in ["nonce", "cipher_text", "mac"]:
            doc = json.loads(FIXTURE["catalog"])
            raw = bytearray(base64.b64decode(doc[field]))
            raw[0] ^= 1
            doc[field] = base64.b64encode(raw).decode()
            with self.assertRaises(catalog.DecodeError) as ctx:
                catalog.decode(json.dumps(doc))
            self.assertEqual(ctx.exception.code, "AUTH_FAILED")

    def test_no_plaintext_fallback_after_failed_gcm_authentication(self):
        doc = json.loads(FIXTURE["catalog"])
        doc["mac"] = base64.b64encode(bytes(16)).decode()
        doc["servers"] = FIXTURE["expectedCatalog"]["servers"]
        self.assertIsNone(catalog.run(json.dumps(doc)))

    def test_invalid_gcm_fields_lengths_and_missing_tag(self):
        for field, value in [("nonce", None), ("nonce", "AA=="), ("cipher_text", 1),
                             ("cipher_text", "!invalid!"), ("mac", 1), ("mac", "AA==")]:
            doc = json.loads(FIXTURE["catalog"])
            doc[field] = value
            self.assertIsNone(catalog.run(json.dumps(doc)))
        doc = {"nonce": base64.b64encode(bytes(12)).decode(), "cipher_text": base64.b64encode(bytes(16)).decode()}
        self.assertIsNone(catalog.run(json.dumps(doc)))

    def test_strict_json_negative_jce_vectors(self):
        for data in FIXTURE["invalidCatalogs"]:
            self.assertIsNone(catalog.run(data))
        for value in ['{"servers":[],"a":1,"a":2}', '{"servers":[],"a":NaN}',
                      '{"servers":[],"a":1e999}', '{"servers":[],"a":"\\ud800"}']:
            self.assertIsNone(catalog.run(value))

    def test_plaintext_catalog_schemas_and_large_lists_preserve_all_members(self):
        for doc in [FIXTURE["expectedCatalog"], {"static_users": [{"id": "synthetic", "month": "1"}]},
                    [{"name": "Synthetic", "key": "preserved"}],
                    {"subscriptions": [{"url": "https://example.invalid/sub", "future": None}]},
                    {"Legacy": "https://example.invalid/sub"},
                    {"servers": [{"id": i} for i in range(1000)], "future": {"keep": True}}]:
            self.assertEqual(catalog.decode(json.dumps(doc)), doc)
        for data in ['{}', 'null', '{"servers":[1]}', '{"static_users":null}', '{"subscriptions":{}}']:
            self.assertIsNone(catalog.run(data))

    def test_five_protocols_from_independent_jce_mkk_vectors(self):
        for vector in FIXTURE["profiles"]:
            self.assertEqual(texts.decrypt_key(vector["data"]), vector["uri"])
            self.assertEqual(texts.decode(vector["data"])["uri"], vector["uri"])
            self.assertEqual(json.loads(texts.run(vector["data"]))["uri"], vector["uri"])

    def test_vmess_unicode_crlf_nested_fields_and_exact_uri(self):
        vector = FIXTURE["profiles"][1]
        result = texts.decode(vector["data"])
        self.assertEqual(result["config"], FIXTURE["expectedVmess"])
        self.assertEqual(result["config"]["payload"], "First\r\nSecond\n")
        self.assertEqual(result["config"]["ps"], "Perú 日本 𝄞")
        self.assertEqual(result["uri"], vector["uri"])

    def test_uri_duplicate_blank_parameters_ipv6_and_decoded_name(self):
        doc = texts.decode(FIXTURE["profiles"][0]["data"])
        self.assertIn("[2001:db8::1]", doc["details"]["authority"])
        self.assertEqual(doc["details"]["query"][-3:], [["x", "1"], ["x", "2"], ["empty", ""]])
        self.assertEqual(doc["details"]["name"], "Perú")

    def test_plain_uri_resolver_and_invalid_vmess_json(self):
        for vector in FIXTURE["profiles"]:
            self.assertEqual(texts.decode(vector["uri"])["uri"], vector["uri"])
        for plain in ['[]', '{"a":1,"a":2}', '{"a":NaN}']:
            self.assertIsNone(texts.run("vmess://" + base64.b64encode(plain.encode()).decode()))
        self.assertIsNone(texts.run("mkk://!invalid!"))
        self.assertIsNone(texts.run("https://example.invalid"))
        self.assertIsNone(texts.run("vmess://" + base64.b64encode(b'\xff\xfe{\x00}\x00').decode()))

    def test_mkk_truncation_cbc_padding_and_wrong_key(self):
        data = FIXTURE["profiles"][0]["data"]
        raw = bytearray(base64.b64decode(data[6:]))
        for broken in [bytes(16), bytes(raw[:-1])]:
            self.assertIsNone(texts.run("mkk://" + base64.b64encode(broken).decode()))
        raw[-17] ^= 128
        self.assertIsNone(texts.run("mkk://" + base64.b64encode(raw).decode()))
        with patch.object(texts, "KEY_MATERIAL", b"foreign-format"):
            self.assertIsNone(texts.run(data))

    def test_original_icon_dimensions_and_checksum(self):
        data = (APP / "MKK_Hyper_VPN.png").read_bytes()
        self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(struct.unpack(">II", data[16:24]), (192, 192))
        self.assertEqual(hashlib.sha256(data).hexdigest(), "ea975a368608e49800eea2877c9966a75b9cc72e0b0d71e3b27e3b55eeb312e6")

    def test_bom_wrapping_padding_and_urlsafe_transport(self):
        data = FIXTURE["profiles"][0]["data"]
        for value in ["\ufeff \r\n" + data + "\n", data.rstrip("="), "mkk://" + data[6:].replace("+", "-").replace("/", "_"),
                      "mkk://" + "\r\n".join(data[i:i+76] for i in range(6, len(data), 76))]:
            self.assertEqual(texts.decode(value)["uri"], FIXTURE["profiles"][0]["uri"])
        self.assertEqual(catalog.decode("\ufeff" + FIXTURE["catalog"]), FIXTURE["expectedCatalog"])

    def test_invalid_input_types_unicode_and_size_bounds(self):
        for module in [catalog, texts]:
            for value in [None, 1, [], b"", b"\xff", b"A", "\ud800"]:
                self.assertIsNone(module.run(value))
            with patch.object(module, "MAX_BYTES", 8):
                self.assertIsNone(module.run(b"x" * 9))
                self.assertIsNone(module.run("日" * 3))

    def test_json_depth_node_and_recursion_limits(self):
        for module in [catalog, texts]:
            with patch.object(module, "MAX_DEPTH", 2):
                with self.assertRaises(module.DecodeError):
                    module._json('{"a":{"b":{"c":1}}}')
            with patch.object(module, "MAX_NODES", 4):
                with self.assertRaises(module.DecodeError):
                    module._json('{"a":1,"b":2}')
            with self.assertRaises(module.DecodeError):
                module._json("[" * 1500 + "0" + "]" * 1500)

    def test_plain_and_base64_subscription_lists_preserve_raw_text_and_duplicates(self):
        uri = FIXTURE["profiles"][0]["uri"]
        body = "# source note\r\n" + uri + "\r\n" + uri + "\n"
        for data in [body, base64.b64encode(body.encode()).decode().rstrip("=")]:
            result = catalog.decode(data)
            self.assertEqual(result["profiles"], [uri, uri])
            self.assertIn("# source note\r\n", result["raw_text"])
            self.assertEqual(result["raw_text"], body)
        self.assertIsNone(catalog.run(base64.b64encode(b"not a subscription")))

    def test_offline_apis_do_not_download_and_text_reader_has_no_network(self):
        self.assertFalse(hasattr(texts, "fetch_catalog"))
        self.assertIsNone(texts.run(FIXTURE["catalog"]))
        self.assertIsNone(catalog.run(FIXTURE["profiles"][0]["data"]))
        with patch.object(catalog, "build_opener", side_effect=AssertionError("unexpected network")):
            self.assertIsNotNone(catalog.run(FIXTURE["catalog"]))
            self.assertIsNotNone(texts.run(FIXTURE["profiles"][0]["data"]))

    def test_http_original_get_headers_timeout_and_read_bound(self):
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

    def test_http_and_redirects_require_https_without_credentials(self):
        req = Request(catalog.CATALOG_URL)
        handler = catalog._HTTPSRedirect()
        with patch.object(catalog, "build_opener", side_effect=AssertionError("unexpected request")):
            for url in ["http://example.invalid", "https://u:p@example.invalid", "https:///missing", "https://example.invalid/#fragment"]:
                with self.assertRaises(catalog.DecodeError):
                    catalog.fetch_catalog(url)
                self.assertIsNone(handler.redirect_request(req, None, 302, "", {}, url))
        self.assertEqual(handler.redirect_request(req, None, 302, "", {}, "https://example.invalid").full_url, "https://example.invalid")

    def test_http_errors_are_sanitized_and_oversized_responses_rejected(self):
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
            with self.assertRaises(catalog.DecodeError):
                catalog.fetch_catalog()

    def test_expansion_preserves_manifest_all_sources_order_and_duplicate_profiles(self):
        doc = {"subscriptions": [{"url": "https://example.invalid/one", "status": "active", "future": None},
                                 {"url": "https://example.invalid/two", "status": "inactive"}], "future": 1}
        body = FIXTURE["profiles"][0]["uri"].encode()
        with patch.object(catalog, "fetch_catalog", return_value=body) as fetch:
            result = catalog.expand_subscriptions(doc)
        self.assertEqual(fetch.call_count, 2)
        self.assertTrue(result["complete"])
        self.assertEqual(result["catalog"], doc)
        self.assertEqual([v["index"] for v in result["sources"]], [0, 1])
        for source in result["sources"]:
            self.assertEqual(source["data"]["profiles"], [body.decode()])

    def test_expansion_never_silently_returns_partial_results(self):
        doc = {"One": "https://example.invalid/one", "Two": "https://example.invalid/two"}
        def fetch(url):
            if url.endswith("two"):
                raise catalog.DecodeError("DOWNLOAD_FAILED", "private-value")
            return FIXTURE["profiles"][0]["uri"].encode()
        with patch.object(catalog, "fetch_catalog", side_effect=fetch):
            with self.assertRaises(catalog.DecodeError) as ctx:
                catalog.expand_subscriptions(doc)
            self.assertEqual(ctx.exception.code, "INCOMPLETE_CATALOG")
            result = catalog.expand_subscriptions(doc, allow_partial=True)
        self.assertFalse(result["complete"])
        self.assertEqual(result["sources"][1], {"index": 1, "status": "error", "error": "DOWNLOAD_FAILED"})
        self.assertNotIn("private-value", json.dumps(result))

    def test_expansion_checks_urls_source_count_and_aggregate_size(self):
        with patch.object(catalog, "fetch_catalog", side_effect=AssertionError("unexpected network")):
            for doc in [{"subscriptions": [{"url": "http://example.invalid"}]}, {"servers": []}]:
                with self.assertRaises(catalog.DecodeError):
                    catalog.expand_subscriptions(doc)
            with patch.object(catalog, "MAX_SOURCES", 0):
                with self.assertRaises(catalog.DecodeError):
                    catalog.expand_subscriptions({"One": "https://example.invalid"})
        with patch.object(catalog, "MAX_TOTAL_BYTES", 1), patch.object(catalog, "fetch_catalog", return_value=b"xx"):
            with self.assertRaises(catalog.DecodeError) as ctx:
                catalog.expand_subscriptions({"One": "https://example.invalid"}, allow_partial=True)
        self.assertEqual(ctx.exception.code, "SIZE_LIMIT")

    def test_standalone_scripts_can_be_copied_separately(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for filename, data in [("MKK_Hyper_VPN.py", FIXTURE["catalog"]),
                                   ("MKK_Hyper_VPN_textos.py", FIXTURE["profiles"][0]["data"])]:
                script = root / filename
                shutil.copyfile(APP / filename, script)
                source, out = root / "input.txt", root / "output.json"
                source.write_text(data)
                proc = subprocess.run([sys.executable, str(script), str(source), "-o", str(out)], cwd=root, capture_output=True, text=True)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                expected = FIXTURE["expectedCatalog"] if filename == "MKK_Hyper_VPN.py" else texts.decode(data)
                self.assertEqual(json.loads(out.read_text()), expected)
                script.unlink()

    def test_cli_text_and_selected_catalog_source(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(texts.main(["--text", FIXTURE["profiles"][0]["data"]]), 0)
        self.assertEqual(json.loads(out.getvalue())["uri"], FIXTURE["profiles"][0]["uri"])
        with patch.object(catalog, "fetch_catalog", return_value=FIXTURE["catalog"]) as fetch, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(catalog.main(["--url", "--source", "static"]), 0)
        fetch.assert_called_once_with(catalog.SOURCES["static"])

    def test_cli_failure_preserves_output_and_reports_missing_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, out = root / "bad.txt", root / "out.json"
            source.write_text("!broken!")
            out.write_text("keep previous")
            for module in [catalog, texts]:
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(module.main([str(source), "-o", str(out)]), 1)
                self.assertIn("error", json.loads(err.getvalue()))
                self.assertEqual(out.read_text(), "keep previous")
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(module.main([str(root / "missing")]), 2)


if __name__ == "__main__":
    unittest.main()
