"""SocketClay 3.4.0 independent vectors, complete results and Cloud integration."""
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
from decoders.Python.apps.HTTP_SocketClay import codec, file_decoder as files, server_catalog_decoder as catalog

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "decoders/Python/apps/HTTP_SocketClay"
V = json.loads((ROOT / "tests/golden/socketclay_vectors.json").read_text("utf-8"))


def wrap_json(text):
    salt = bytes(range(8))
    material = previous = b""
    while len(material) < 48:
        previous = hashlib.md5(previous + codec.CATALOG_PASSWORD + salt).digest()
        material += previous
    return base64.b64encode(b"WakkoDev" + salt + AES.new(material[:32], AES.MODE_CBC, material[32:48]).encrypt(pad(text.encode(), 16)))


class SocketClayTests(unittest.TestCase):
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
        self.assertEqual(len(codec.SERVER_FIELDS), 27)
        self.assertEqual(len(codec.USER_FIELDS), 7)
        self.assertEqual([e["serverType"] for e in V["expectedCatalog"]["Servers"]], [1, 2, 3, 4])
        self.assertIsInstance(V["expectedCatalog"]["Servers"][0]["serverType"], int)

    def test_wrapped_fields_authenticate_nonce_ciphertext_tag_without_cbc_fallback(self):
        v = next(v for v in V["fieldVectors"] if v["wrapped"])
        original = codec.shared._base64(v["cipher"], urlsafe=True)
        for pos in (0, 12, len(original) - 1):
            raw = bytearray(original); raw[pos] ^= 1
            changed = base64.urlsafe_b64encode(raw).decode().rstrip("=")
            with patch.object(codec.AES, "new", side_effect=AssertionError("CBC fallback")):
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

    def test_both_shared_sks_formats_preserve_xml_duplicates_empty_and_multiline(self):
        for data in (V["profileGcm"].encode(), base64.b64decode(V["profileDesBase64"])):
            self.assertEqual(json.loads(files.run(data)), V["expectedProfile"])
        self.assertEqual([e["value"] for e in V["expectedProfile"]["entries"] if e["key"] == "dup"], ["first", "second"])

    def test_sks_gcm_tamper_is_rejected_without_legacy_des_retry(self):
        parts = V["profileGcm"].encode().split(b".")
        for pos in range(3):
            changed = parts.copy(); raw = bytearray(base64.b64decode(changed[pos])); raw[-1] ^= 1
            changed[pos] = base64.b64encode(raw)
            with patch.object(codec.shared.DES, "new", side_effect=AssertionError("DES fallback")):
                with self.assertRaises(codec.DecodeError): files.run(b".".join(changed))

    def test_input_and_output_limits(self):
        for run, limit in ((files.run, codec.MAX_FILE_BYTES), (catalog.run, codec.MAX_BYTES)):
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

    def test_isolated_worker_catalog_and_shared_sks_route_return_complete_json(self):
        sys.path.insert(0, str(ROOT / "cloud/workers/python"))
        from engine import decode_file, decode_provider_catalog
        result = decode_provider_catalog("http-socketclay", V["catalog"].encode())
        self.assertEqual(result["structuredJson"], V["expectedCatalog"]); self.assertFalse(result["isPartial"])
        for data in (V["profileGcm"].encode(), base64.b64decode(V["profileDesBase64"])):
            result = decode_file("sks", data)
            self.assertEqual(result["structuredJson"], V["expectedProfile"]); self.assertFalse(result["isPartial"])

    def test_standalone_cli_file_stdin_and_private_error_sanitization(self):
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        cases = [("file_decoder.py", V["profileGcm"].encode(), V["expectedProfile"], []),
                 ("server_catalog_decoder.py", V["catalog"].encode(), V["expectedCatalog"], ["--stdin"])]
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
        text = "".join("\t".join([cmd] + [base64.b64encode(v.encode()).decode() for v in values]) + "\n" for cmd, values in tasks)
        proc = subprocess.run(["java", str(ROOT / "tests/golden/socketclay_oracle.java")], input=text, text=True, capture_output=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        values = [base64.b64decode(line) for line in proc.stdout.splitlines()]
        self.assertEqual(json.loads(values[0]), json.loads(codec.decrypt_catalog(V["catalog"].encode())))
        count = len(V["keyVectors"])
        self.assertEqual(values[1:1+count], [base64.b64decode(v["keyBase64"]) for v in V["keyVectors"]])
        self.assertEqual([v.decode() for v in values[1+count:]], [v["plain"] for v in V["fieldVectors"]])

    def test_combined_catalogs_use_independent_versions_and_preserve_both_documents(self):
        server_v = next(v for v in V["fieldVectors"] if v["version"] == "1")
        user_v = next(v for v in V["fieldVectors"] if v["version"] == "341")
        name = codec._names["servers"]["sName"]
        servers = {"Version": "1", "Servers": [{name: server_v["cipher"], "unknown": [None, False]}], "ReleaseNotes": "Synthetic"}
        users = {"Version": "341", "Usuarios": [{"Name": user_v["cipher"]}], "unknown": {"keep": True}}
        bundle = catalog.pack_catalogs(wrap_json(json.dumps(servers)), wrap_json(json.dumps(users)))
        expected_s = {**servers, "Servers": [{name: server_v["plain"], "unknown": [None, False]}]}
        expected_u = {**users, "Usuarios": [{"Name": user_v["plain"]}]}
        expected = {"provider": "http-socketclay", "complete": True, "catalogs": {"servers": expected_s, "users": expected_u}}
        self.assertEqual(json.loads(catalog.run(bundle)), expected)
        sys.path.insert(0, str(ROOT / "cloud/workers/python"))
        from engine import decode_provider_catalog
        result = decode_provider_catalog("http-socketclay", bundle)
        self.assertEqual(result["structuredJson"], expected)
        self.assertFalse(result["isPartial"])

    def test_combined_catalog_rejects_missing_corrupt_swapped_or_ambiguous_sources(self):
        data = V["catalog"].encode()
        bundle = json.loads(catalog.pack_catalogs(data, data))
        bad = [b'{"kind":"spdecode-socketclay-catalogs-v1","kind":"fake","catalogs":{}}']
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
        icon = (APP / "HTTP_SocketClay.png").read_bytes()
        self.assertEqual(icon, (ROOT / "cloud/web/public/server-vpn-icons/http-socketclay.png").read_bytes())
        self.assertEqual(hashlib.sha256(icon).hexdigest(), "8a09f5b74e445f859532809204c3a543b05b6fa89be8844b655191e17690f101")


if __name__ == "__main__": unittest.main()
