"""HA 1.7.1 catalog and open-layout export; public synthetic fixtures only."""
import base64
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from decoders.Python.apps.HA_Tunnel_Plus import server_catalog_decoder as catalog
from decoders.Python.apps.HA_Tunnel_Plus import hat_decoder as hat
from cloud.workers.python.exports.hat import export
from cloud.workers.python.exports.lossless import equal
from cloud.workers.python.engine import decode_file, decode_provider_catalog

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'cloud/workers/python'))


def seal(raw):
    if isinstance(raw, dict):
        raw = json.dumps(raw, ensure_ascii=False, separators=(",", ":")).encode()
    return base64.b64encode(AES.new(base64.b64decode("zbNkuNCGSLivpEuep3BcNA=="), AES.MODE_ECB).encrypt(pad(raw, 16)))


def hidden(text):
    # Independent UTF-16 char semantics matching Java HideUtil.
    units = text.encode("utf-16-le"); key = "**rVg7EkL~c2`D[aNn".encode("utf-16-le")
    encoded = bytes(b ^ key[i % len(key)] for i, b in enumerate(units)).decode("utf-16-le")
    return base64.b64encode(encoded.encode()).decode()


PROFILE = {"connection_mode": "ssl", "custom_payload": "GET / 🚀 HTTP/1.1\r\nHost: example.test\r\n\r\n",
           "custom_host": "edge.example.test", "custom_sni": "example.test", "server_port": 443,
           "future": {"port": 8080, "keep": [False, 0, None, "café"]}}


def locked():
    profile = copy.deepcopy(PROFILE)
    for key in hat.PROFILE_FIELDS:
        profile[key] = hidden(profile[key])
    return {"profile": {}, "profilev5": profile, "description": "old compatibility warning",
            "descriptionv5": "original note", "protextras": {
                "anti_sniff": True, "mobile_data": True, "block_root": True,
                "password": True, "password_value": "synthetic-hash", "id_lock": True,
                "id_lock_value": "synthetic-hash", "expiry": True, "expiry_value": 1},
            "unknown": {"nested": [False, None, 123456789012345678901234567890]}}


def catalog_fixture():
    methods = {"version": "synthetic.1", "data": [{"name": "test", "conf": {"custom_sni": "example.test"}}], "unknown": [None, False]}
    # Native key is SHA1(3A0183FADC903782)[:16], independently fixed below.
    key = bytes.fromhex("caf88ec7d2df3146e082dbfc89ff1430")
    cipher = base64.b64encode(AES.new(key, AES.MODE_ECB).encrypt(pad(json.dumps(methods).encode(), 16))).decode()
    outer = {"servers": {"version": "s1", "data": [{"node": "example.test"}], "keep": 7},
             "methods": cipher, "allowed_apps": {"version": "a1", "data": {"group": [{"package": "example.app"}]}},
             "message": "unchanged", "future": {"n": [False, 0]}}
    expected = copy.deepcopy(outer); expected["methods"] = methods
    return outer, expected


class HaCatalogExportTests(unittest.TestCase):
    def test_catalog_complete_and_android_literal_linefeed(self):
        outer, expected = catalog_fixture()
        for strings in (False, True):
            doc = copy.deepcopy(outer)
            if strings:
                for key in ("servers", "allowed_apps"):
                    doc[key] = json.dumps(doc[key])
            raw = json.dumps(doc).replace(outer["methods"], outer["methods"][:20] + "\n" + outer["methods"][20:]).encode()
            self.assertTrue(equal(catalog.decode_catalog(raw), expected))
            worker = decode_provider_catalog("ha-tunnel-plus", raw)
            self.assertFalse(worker["isPartial"])
            self.assertTrue(equal(worker["structuredJson"], expected))

    def test_catalog_rejects_incomplete_corrupt_duplicate_and_html(self):
        outer, _ = catalog_fixture()
        bad = [b"<html>unavailable</html>", b'{"servers":{},"servers":{}}', b"{}", b"NaN"]
        for key in ("servers", "methods", "allowed_apps"):
            doc = dict(outer); del doc[key]; bad.append(json.dumps(doc).encode())
        doc = dict(outer); doc["methods"] = "bad base64!"; bad.append(json.dumps(doc).encode())
        for raw in bad:
            with self.subTest(raw_size=len(raw)), self.assertRaises(ValueError):
                catalog.decode_catalog(raw)

    def test_fixed_download_recipe_and_no_redirect(self):
        class Response:
            status = 200
            headers = {}
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, limit): self.limit = limit; return b"catalog-bytes"
        class Opener:
            def open(self, request, timeout):
                self.request, self.timeout = request, timeout
                return Response()
        opener = Opener()
        with patch.object(catalog, "build_opener", return_value=opener):
            self.assertEqual(catalog.download(), b"catalog-bytes")
        self.assertEqual(opener.request.full_url, "https://www.hatunnel.me/resources/main.txt")
        self.assertEqual(opener.request.get_method(), "GET")
        self.assertIsNone(opener.request.data)
        self.assertEqual(opener.request.get_header("User-agent"), "Dalvik/2.1.0")
        with self.assertRaises(ValueError): catalog._NoRedirect().redirect_request()

    def test_open_export_preserves_every_connection_field_and_metadata(self):
        source = locked(); output = export(seal(source), {})
        decoded = hat.decode_hat(output)
        self.assertTrue(equal(decoded["profile"], PROFILE))
        self.assertEqual(decoded["description"], "original note")
        self.assertEqual(decoded["unknown"], source["unknown"])
        self.assertEqual(set(decoded), {"profile", "description", "unknown"})
        self.assertEqual(export(output, {}), output)

    def test_unknown_raw_number_tokens_and_plain_base64_text_are_preserved(self):
        source = b'{"profile":{"custom_payload":"YWJj","unknown":1.2300000000000000001e+27},"future":1e-400,"description":"keep"}'
        out = export(seal(source), {})
        clear = unpad(AES.new(hat.KEY, AES.MODE_ECB).decrypt(base64.b64decode(out)), 16)
        self.assertEqual(clear, source)

    def test_unsupported_or_ambiguous_layout_never_generates_partial_export(self):
        variants = []
        for mutate in (lambda x: x["profilev5"].pop("custom_host"),
                       lambda x: x["profilev5"].update(custom_host="bad!"),
                       lambda x: x["protextras"].update(unknown_future=True),
                       lambda x: x.update(profile={"different": True}),
                       lambda x: x.update(profilev4={"different": True})):
            x = locked(); mutate(x); variants.append(seal(x))
        variants += [b"not-a-hat", seal(b'{"profile":{},"profile":{}}')]
        for raw in variants:
            with self.assertRaises(ValueError): export(raw, {})
        with self.assertRaises(ValueError): export(seal(locked()), {"password": "unused"})

    def test_worker_export_binds_source_and_full_result(self):
        raw = seal(locked())
        result = decode_file("hat", raw, compatible_export={"profile": "original-app-open-v1"})
        artifact = result["compatibleExport"]
        self.assertEqual(artifact["status"], "ready")
        self.assertEqual(artifact["targetAppId"], "ha-tunnel-plus")
        self.assertEqual(artifact["targetAppName"], "HA Tunnel Plus")
        self.assertEqual(artifact["extension"], ".hat")
        self.assertFalse(result["isPartial"])
        self.assertIn("unknown", result["structuredJson"])
        self.assertTrue(equal(hat.decode_hat(base64.b64decode(artifact["dataBase64"]))["profile"], PROFILE))


if __name__ == "__main__":
    unittest.main()
