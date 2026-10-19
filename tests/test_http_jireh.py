"""HTTP Jireh 2.0 vectors: Java parity, whole documents and Cloud routing."""
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
from decoders.Python.apps.HTTP_Jireh import codec, file_decoder as files, server_catalog_decoder as catalog

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "decoders/Python/apps/HTTP_Jireh"
V = json.loads((ROOT / "tests/golden/jireh_vectors.json").read_text("utf-8"))


def wrap_json(text):
    raw = AES.new(codec.CATALOG_KEY, AES.MODE_CBC, bytes(16)).encrypt(pad(text.encode(),16))
    return "".join(codec.ALPHABET[b >> 4] + codec.ALPHABET[b & 15] for b in base64.b64encode(raw)).encode()


def wrap_profile(text):
    salt, nonce = bytes(range(32)), bytes(range(12))
    key = hashlib.pbkdf2_hmac("sha256", codec.shared.PROFILE_PASSWORD, salt, 1000, 16)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    sealed, tag = cipher.encrypt_and_digest(text.encode())
    return b".".join(base64.b64encode(v) for v in (salt, nonce, sealed + tag))


class JirehTests(unittest.TestCase):
    def test_java_field_and_utf16_rotation_vectors(self):
        for v in V["fieldVectors"]:
            self.assertEqual(codec.decode_field(v["cipher"]), v["plain"])
        for v in V["rotationVectors"]:
            self.assertEqual(codec.shared.rotate_java(v["input"], 22), v["expected"])
        self.assertEqual(codec.decode_field(""), "")

    def test_complete_catalog_preserves_opaque_keys_plain_names_flags_and_unknowns(self):
        with patch.object(catalog, "download", side_effect=AssertionError("offline")):
            obj = json.loads(catalog.run(V["catalog"].encode()))
        self.assertEqual(obj, V["expectedCatalog"])
        self.assertEqual(obj["Usuarios"][0]["Name"], "Usuario sintético ñ")
        self.assertEqual(obj["Servers"][0]["Unknown"]["keep"], [True, None, 0])
        self.assertEqual(len(codec.SERVER_FIELDS), 16)
        self.assertEqual(len(codec.USER_FIELDS), 6)

    def test_both_sks_formats_preserve_xml_entries_duplicates_empty_and_unicode(self):
        for data in (V["profileGcm"].encode(), base64.b64decode(V["profileDesBase64"])):
            self.assertEqual(json.loads(files.run(data)), V["expectedProfile"])
        entries = V["expectedProfile"]["entries"]
        self.assertEqual([x["value"] for x in entries if x["key"] == "dup"], ["first", "second"])
        self.assertEqual(next(x["value"] for x in entries if x["key"] == "empty"), "")
        self.assertEqual(V["expectedProfile"]["raw_xml"], V["profileXml"])

    def test_gcm_authenticates_every_component_and_never_retries_des(self):
        pieces = V["profileGcm"].encode().split(b".")
        for part in range(3):
            changed = pieces.copy()
            raw = bytearray(base64.b64decode(changed[part])); raw[-1] ^= 1
            changed[part] = base64.b64encode(raw)
            with patch.object(codec.shared.DES, "new", side_effect=AssertionError("fallback")):
                with self.assertRaises(codec.DecodeError): files.run(b".".join(changed))
        for data in (b"x.y.z", b"".join(pieces), V["profileGcm"].encode()[:-12], b"12345678"):
            with self.assertRaises(codec.DecodeError): files.run(data)

    def test_catalog_rejects_padding_header_html_truncation_and_bad_known_field(self):
        raw = bytearray(V["catalog"].encode()); raw[0] = ord("!") if raw[0] != ord("!") else ord("@")
        for data in (bytes(raw), b"<html>error</html>", b"broken", V["catalog"].encode()[:-12], b"@@@", b"x"*32):
            with self.assertRaises(codec.DecodeError): catalog.run(data)
        obj = json.loads(codec.decrypt_catalog(V["catalog"].encode()))
        key = next(iter(codec.SERVER_FIELDS))
        for value in (True, "broken", "fake-private-input"):
            obj["Servers"][0][key] = value
            with self.assertRaises(codec.DecodeError) as error:
                catalog.run(wrap_json(json.dumps(obj)))
            self.assertNotIn("fake-private-input", str(error.exception))

    def test_catalog_rejects_duplicate_keys_bad_lists_nonfinite_and_depth(self):
        invalid = ['{"Version":"1","Version":"2","Servers":[{}]}',
                   '{"Version":"1","Servers":[{"unknown":1}]}',
                   '{"Version":"1","Servers":[]}', '{"Version":"1","Usuarios":[null]}',
                   '{"Version":"1","Usuarios":[{"Name":"x"}],"unknown":NaN}',
                   '{"Version":"1","Usuarios":[{"Name":"x"}],"unknown":1e999}']
        for text in invalid:
            with self.assertRaises(codec.DecodeError): catalog.run(wrap_json(text))
        obj = {"Version": "1", "Usuarios": [{"Name": "x"}], "unknown": [[0]]}
        for _ in range(65): obj["unknown"] = [obj["unknown"]]
        with self.assertRaises(codec.DecodeError): catalog.run(wrap_json(json.dumps(obj)))

    def test_properties_parser_rejects_entities_wrong_root_and_empty_document(self):
        for text in ('<root><entry key="x">x</entry></root>', '<properties/>',
                     '<!DOCTYPE properties [<!ENTITY x "boom">]><properties><entry key="x">&x;</entry></properties>',
                     '<properties><entry key="x"><extra/></entry></properties>'):
            with self.assertRaises(codec.DecodeError): files.run(wrap_profile(text))

    def test_input_and_output_limits(self):
        for run, limit in ((files.run, codec.MAX_FILE_BYTES), (catalog.run, codec.MAX_BYTES)):
            for data in (b"", b"x" * (limit + 1)):
                with self.assertRaises(codec.DecodeError): run(data)
        with self.assertRaises(codec.DecodeError): codec.render({"x": "x" * codec.MAX_BYTES})

    def test_downloader_uses_two_fixed_urls_and_denies_bad_responses(self):
        class Response:
            status = 200
            headers = {}
            data = V["catalog"].encode()
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size): return self.data[:size]
        class Opener:
            seen = []
            def open(self, request, timeout):
                self.seen.append(request.full_url)
                if timeout != 25: raise AssertionError("deadline")
                return Response()
        opener = Opener()
        with patch.object(catalog, "build_opener", return_value=opener):
            self.assertEqual(catalog.download(), V["catalog"].encode())
            catalog.download(users=True)
            self.assertEqual(opener.seen, [catalog.CATALOG_URL, catalog.USERS_URL])
            for bad in (b"", b"<html/>", b"x" * (codec.MAX_BYTES + 1)):
                with patch.object(Response, "data", bad), self.assertRaises(codec.DecodeError): catalog.download()
            with patch.object(Response, "headers", {"Content-Encoding": "gzip"}), self.assertRaises(codec.DecodeError): catalog.download()
        with self.assertRaises(codec.DecodeError): catalog._NoRedirect().redirect_request(None, None, 302, "", {}, "https://example.invalid")

    def test_actual_worker_routes_sks_and_complete_catalog(self):
        sys.path.insert(0, str(ROOT / "cloud/workers/python"))
        from engine import decode_file, decode_provider_catalog
        for data in (V["profileGcm"].encode(), base64.b64decode(V["profileDesBase64"])):
            result = decode_file("sks", data)
            self.assertEqual(result["structuredJson"], V["expectedProfile"])
            self.assertFalse(result["isPartial"])
        result = decode_provider_catalog("http-jireh", V["catalog"].encode())
        self.assertEqual(result["structuredJson"], V["expectedCatalog"])
        self.assertFalse(result["isPartial"])

    def test_cli_is_offline_with_file_or_stdin_and_sanitizes_errors(self):
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        for script, data, expected in (("file_decoder.py", V["profileGcm"].encode(), V["expectedProfile"]),
                                       ("server_catalog_decoder.py", V["catalog"].encode(), V["expectedCatalog"])):
            args = [sys.executable, str(APP / script)] + (["--stdin"] if "catalog" in script else [])
            result = subprocess.run(args, input=data, capture_output=True, env=env, cwd="/tmp", timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(json.loads(result.stdout), expected)
            bad = subprocess.run(args, input=b"fake-private-input", capture_output=True, env=env, cwd="/tmp", timeout=10)
            self.assertNotEqual(bad.returncode, 0)
            self.assertEqual(bad.stdout, b"")
            self.assertNotIn(b"fake-private-input", bad.stderr)

    @unittest.skipUnless(shutil.which("java"), "Java source launcher not installed")
    def test_java_oracle_reproduces_committed_synthetic_vectors(self):
        pairs = [("outer", V["catalog"]), ("profile-decrypt", V["profileGcm"]),
                 ("des-decrypt", V["profileDesBase64"])]
        pairs += [("field", v["cipher"]) for v in V["fieldVectors"]]
        pairs += [("rotate", v["input"]) for v in V["rotationVectors"]]
        text = "".join(k + "\t" + base64.b64encode(v.encode()).decode() + "\n" for k, v in pairs)
        result = subprocess.run(["java", str(ROOT / "tests/golden/jireh_oracle.java")], input=text, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        decoded = [base64.b64decode(v).decode() for v in result.stdout.splitlines()]
        self.assertEqual(json.loads(decoded[0]), json.loads(codec.decrypt_catalog(V["catalog"].encode())))
        self.assertEqual(decoded[1:3], [V["profileXml"]] * 2)
        self.assertEqual(decoded[3:3 + len(V["fieldVectors"])], [v["plain"] for v in V["fieldVectors"]])
        self.assertEqual(decoded[3 + len(V["fieldVectors"]):], [v["expected"] for v in V["rotationVectors"]])

    def test_original_icon_is_identical_in_app_and_public_catalog(self):
        icon = (APP / "HTTP_Jireh.png").read_bytes()
        self.assertEqual(icon, (ROOT / "cloud/web/public/server-vpn-icons/http-jireh.png").read_bytes())
        self.assertEqual(hashlib.sha256(icon).hexdigest(), "91d4b152a6087a0b60656de9d03444c60199ab4928d8af0c517ab5be0270088e")


if __name__ == "__main__":
    unittest.main()
