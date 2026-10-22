"""HTTP Wakko 4.9: full APK-specific fields, independent vectors and Cloud parity."""
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
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from decoders.Python.apps.HTTP_Wakko import codec, server_catalog_decoder as catalog

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "decoders/Python/apps/HTTP_Wakko"
V = json.loads((ROOT / "tests/golden/wakko_vectors.json").read_text("utf-8"))


def wrap_json(text):
    salt = bytes(range(8))
    material = previous = b""
    while len(material) < 48:
        previous = hashlib.md5(previous + codec.crypto.CATALOG_PASSWORD + salt).digest()
        material += previous
    return base64.b64encode(b"WakkoDev" + salt + AES.new(material[:32], AES.MODE_CBC, material[32:48]).encrypt(pad(text.encode(), 16)))


class WakkoTests(unittest.TestCase):
    def test_native_checked_version_key_vectors_and_java_fields(self):
        for v in V["keyVectors"]:
            self.assertEqual(codec.field_key(v["version"]), base64.b64decode(v["keyBase64"]))
        for v in V["fieldVectors"]:
            self.assertEqual(codec.decode_field(v["cipher"], codec.field_key(v["version"])), v["plain"])
        for v in V["rotationVectors"]:
            self.assertEqual(codec.shared.rotate_java(v["input"], 19), v["expected"])
        self.assertEqual(codec.decode_field("", codec.field_key("1")), "")
        for version in (None, True, 1, "", "x" * 129):
            with self.assertRaises(codec.DecodeError): codec.field_key(version)

    def test_complete_catalog_preserves_all_keys_types_and_nested_unknowns_offline(self):
        with patch.object(catalog, "download", side_effect=AssertionError("network")):
            self.assertEqual(json.loads(catalog.run(V["catalog"].encode())), V["expectedCatalog"])
        self.assertEqual(len(codec.SERVER_FIELDS), 29)
        self.assertEqual(len(codec.USER_FIELDS), 7)
        self.assertEqual([e["serverType"] for e in V["expectedCatalog"]["Servers"]], [1, 2, 3, 4, 5])
        self.assertIsInstance(V["expectedCatalog"]["Servers"][0]["serverType"], int)

    def test_wrapped_fields_authenticate_nonce_ciphertext_tag_without_cbc_fallback(self):
        v = next(v for v in V["fieldVectors"] if v["wrapped"])
        original = codec.shared._base64(v["cipher"], urlsafe=True)
        for pos in (0, 12, len(original) - 1):
            raw = bytearray(original); raw[pos] ^= 1
            changed = base64.urlsafe_b64encode(raw).decode().rstrip("=")
            with patch.object(codec.crypto.AES, "new", side_effect=AssertionError("CBC fallback")):
                with self.assertRaises(ValueError): codec.decode_field(changed, codec.field_key(v["version"]))

    def test_corrupt_known_field_wrong_version_padding_and_header_never_return_partial(self):
        wire = json.loads(codec.decrypt_catalog(V["catalog"].encode()))
        field = next(iter(codec.SERVER_FIELDS))
        for value in (True, "fake-private-input", ["x"]):
            obj = json.loads(json.dumps(wire)); obj["Servers"][0][field] = value
            with self.assertRaises(codec.DecodeError) as error: catalog.run(wrap_json(json.dumps(obj)))
            self.assertNotIn("fake-private-input", str(error.exception))
        obj = {**wire, "Version": "wrong-version"}
        with self.assertRaises(codec.DecodeError): catalog.run(wrap_json(json.dumps(obj)))
        raw = bytearray(base64.b64decode(V["catalog"]))
        for pos in (0, len(raw) - 1):
            bad = raw.copy(); bad[pos] ^= 1
            with self.assertRaises(codec.DecodeError): catalog.run(base64.b64encode(bad))
        for data in (b"<html>private</html>", b"broken", V["catalog"].encode()[:-12]):
            with self.assertRaises(codec.DecodeError): catalog.run(data)

    def test_json_duplicates_nonfinite_empty_lists_depth_and_version_are_rejected(self):
        bad = ['{"Version":"1","Version":"2","Servers":[{}]}',
               '{"Version":"1","Servers":[{"unknown":1}]}',
               '{"Version":"1","Servers":[]}', '{"Version":"1","Usuarios":[null]}',
               '{"Version":"1","Usuarios":[{"Name":""}],"unknown":NaN}',
               '{"Version":"1","Usuarios":[{"Name":""}],"unknown":1e999}',
               '{"Version":1,"Usuarios":[{"Name":""}]}']
        for text in bad:
            with self.assertRaises(codec.DecodeError): catalog.run(wrap_json(text))
        obj = {"Version": "1", "Usuarios": [{"Name": ""}], "unknown": [0]}
        for _ in range(65): obj["unknown"] = [obj["unknown"]]
        with self.assertRaises(codec.DecodeError): catalog.run(wrap_json(json.dumps(obj)))

    def test_empty_optional_fields_remain_empty_and_opaque_unknown_values_stay_opaque(self):
        obj = json.loads(codec.decrypt_catalog(V["catalog"].encode()))
        for key in codec.SERVER_FIELDS: obj["Servers"][0][key] = ""
        expected = V["expectedCatalog"]["Servers"][0].copy()
        for key in codec.SERVER_FIELDS: expected[key] = ""
        result = codec.decode_catalog(wrap_json(json.dumps(obj)))
        self.assertEqual(result["Servers"][0], expected)



    def test_input_and_output_limits(self):
        for run, limit in ((catalog.run, codec.MAX_BYTES),):
            for data in (b"", b"x" * (limit + 1)):
                with self.assertRaises(codec.DecodeError): run(data)
        with self.assertRaises(codec.DecodeError): codec.render({"x": "x" * codec.MAX_BYTES})

    def test_both_fixed_catalog_downloads_are_supported_and_unexpected_redirects_stay_blocked(self):
        class Response:
            status = 200
            headers = {}
            data = V["catalog"].encode()
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size): return self.data[:size]
        class Opener:
            def open(self, request, timeout):
                self.url = request.full_url
                self.timeout = timeout
                return Response()
        opener = Opener()
        with patch.object(catalog, "build_opener", return_value=opener):
            self.assertEqual(catalog.download(), V["catalog"].encode())
            self.assertEqual(opener.url, catalog.CATALOG_URL); self.assertEqual(opener.timeout, 25)
            self.assertEqual(catalog.download(users=True), V["catalog"].encode())
            self.assertEqual(opener.url, catalog.USERS_URL)
            for bad in (b"", b"<html/>", b"x" * (codec.MAX_BYTES + 1)):
                with patch.object(Response, "data", bad), self.assertRaises(codec.DecodeError): catalog.download()
            for bad in ({"Content-Encoding": "gzip"},):
                with patch.object(Response, "headers", bad), self.assertRaises(codec.DecodeError): catalog.download()
            with patch.object(Response, "status", 403), self.assertRaises(codec.DecodeError): catalog.download()
        with self.assertRaises(codec.DecodeError): catalog._NoRedirect().redirect_request(None, None, 302, "", {}, "https://example.invalid")

    def test_isolated_worker_returns_the_complete_catalog(self):
        sys.path.insert(0, str(ROOT / "cloud/workers/python"))
        from engine import decode_provider_catalog
        result = decode_provider_catalog("http-wakko", V["catalog"].encode())
        self.assertEqual(result["structuredJson"], V["expectedCatalog"])
        self.assertFalse(result["isPartial"])

    def test_standalone_cli_file_stdin_and_private_error_sanitization(self):
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        cases = [("server_catalog_decoder.py", V["catalog"].encode(), V["expectedCatalog"], ["--stdin"])]
        with tempfile.TemporaryDirectory() as folder:
            for script, data, expected, flags in cases:
                for file_mode in (False, True):
                    source = Path(folder) / "sample.enc"; source.write_bytes(data)
                    args = [sys.executable, str(APP / script)] + ([str(source)] if file_mode else flags)
                    result = subprocess.run(args, input=data, capture_output=True, env=env, cwd=folder, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr.decode()); self.assertEqual(json.loads(result.stdout), expected)
                bad = subprocess.run([sys.executable, str(APP / script), *flags], input=b"fake-private-input", capture_output=True, env=env, cwd=folder, timeout=10)
                self.assertNotEqual(bad.returncode, 0); self.assertEqual(bad.stdout, b""); self.assertNotIn(b"fake-private-input", bad.stderr)

    @unittest.skipUnless(shutil.which("java"), "JDK source launcher not available")
    def test_independent_java_oracle_reproduces_all_synthetic_vectors(self):
        tasks = [("outer", [V["catalog"]])]
        tasks += [("key", [v["version"]]) for v in V["keyVectors"]]
        tasks += [("field", [v["version"], v["cipher"]]) for v in V["fieldVectors"]]
        whole = []
        for encoded in (V["catalog"], V["usersCatalog"]):
            doc = json.loads(codec.decrypt_catalog(encoded.encode()))
            for group, fields in (("Servers", codec.SERVER_FIELDS), ("Usuarios", codec.USER_FIELDS)):
                for entry in doc.get(group, []):
                    for field in fields & entry.keys():
                        if entry[field]: whole.append((doc["Version"], entry[field], codec.decode_field(entry[field], codec.field_key(doc["Version"]))))
        tasks += [("field", [version, cipher]) for version, cipher, plain in whole]
        text = "".join("\t".join([cmd] + [base64.b64encode(v.encode()).decode() for v in values]) + "\n" for cmd, values in tasks)
        proc = subprocess.run(["java", str(ROOT / "tests/golden/wakko_oracle.java")], input=text, text=True, capture_output=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        values = [base64.b64decode(line) for line in proc.stdout.splitlines()]
        self.assertEqual(json.loads(values[0]), json.loads(codec.decrypt_catalog(V["catalog"].encode())))
        count = len(V["keyVectors"])
        self.assertEqual(values[1:1+count], [base64.b64decode(v["keyBase64"]) for v in V["keyVectors"]])
        self.assertEqual([v.decode() for v in values[1+count:]], [v["plain"] for v in V["fieldVectors"]] + [plain for _, _, plain in whole])

    def test_combined_catalogs_use_independent_versions_and_preserve_both_documents(self):
        bundle = catalog.pack_catalogs(V["catalog"].encode(), V["usersCatalog"].encode())
        expected = {"provider": "http-wakko", "complete": True, "catalogs": {
            "servers": V["expectedCatalog"], "users": V["expectedUsers"]}}
        self.assertNotEqual(expected["catalogs"]["servers"]["Version"], expected["catalogs"]["users"]["Version"])
        self.assertEqual(json.loads(catalog.run(bundle)), expected)
        sys.path.insert(0, str(ROOT / "cloud/workers/python"))
        from engine import decode_provider_catalog
        result = decode_provider_catalog("http-wakko", bundle)
        self.assertEqual(result["structuredJson"], expected)
        self.assertFalse(result["isPartial"])

    def test_bhttp_slots_decrypt_and_empty_values_stay_empty_without_ui_defaults(self):
        expected = V["expectedCatalog"]["Servers"][-1]
        for name, value in (("BhttpUpSlot", "23"), ("BhttpDownSlot", "47")):
            field = codec._names["servers"][name]
            self.assertEqual(expected[field], value)
            wire = json.loads(codec.decrypt_catalog(V["catalog"].encode()))
            wire["Servers"][-1][field] = ""
            self.assertEqual(codec.decode_catalog(wrap_json(json.dumps(wire)))["Servers"][-1][field], "")
            wire["Servers"][-1][field] = "corrupt-bhttp-slot"
            with self.assertRaises(codec.DecodeError): catalog.run(wrap_json(json.dumps(wire)))

    def test_combined_catalog_rejects_missing_corrupt_swapped_or_ambiguous_sources(self):
        data = V["catalog"].encode()
        bundle = json.loads(catalog.pack_catalogs(data, data))
        bad = [b'{"kind":"spdecode-wakko-catalogs-v1","kind":"fake","catalogs":{}}']
        for name in ("servers", "users"):
            missing = json.loads(json.dumps(bundle)); del missing["catalogs"][name]
            bad.append(json.dumps(missing).encode())
            corrupt = json.loads(json.dumps(bundle)); corrupt["catalogs"][name] = "!"
            bad.append(json.dumps(corrupt).encode())
        only_servers = json.loads(codec.decrypt_catalog(data)); del only_servers["Usuarios"]
        wrong = {**bundle, "catalogs": {**bundle["catalogs"], "users": base64.b64encode(wrap_json(json.dumps(only_servers))).decode()}}
        bad.append(json.dumps(wrong).encode())
        for payload in bad:
            with self.assertRaises(codec.DecodeError): catalog.run(payload)
        with self.assertRaises(codec.DecodeError): catalog.pack_catalogs(b"", data)
        with self.assertRaises(codec.DecodeError): catalog.pack_catalogs(b"x" * (4*1024*1024), b"x" * (4*1024*1024))

    def test_cli_default_downloads_both_catalogs_and_users_flag_selects_users(self):
        data = V["catalog"].encode()
        for flags, calls in (([], [False, True]), (["--all"], [False, True]), (["--users"], [True]), (["--download"], [False])):
            seen = []
            def download(*, users=False):
                seen.append(users)
                return data
            with patch.object(catalog, "download", side_effect=download), patch.object(sys, "argv", ["catalog", *flags]), patch("sys.stdout"):
                self.assertEqual(catalog.main(), 0)
            self.assertEqual(seen, calls)

    def test_original_icon_matches_manifest_and_cloud_bytes(self):
        original = (APP / "HTTP_Wakko.webp").read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(), "67e597e008e6f275edfdc1a143d352430b8f68048848cda1dbe840d27b54fa4e")
        icon = (APP / "HTTP_Wakko.png").read_bytes()
        self.assertEqual(icon, (ROOT / "cloud/web/public/server-vpn-icons/http-wakko.png").read_bytes())
        self.assertEqual(hashlib.sha256(icon).hexdigest(), "77d7f0647746000fea1dee4ae0dff7189214e649944de226fc07d864971f520a")


if __name__ == "__main__": unittest.main()
