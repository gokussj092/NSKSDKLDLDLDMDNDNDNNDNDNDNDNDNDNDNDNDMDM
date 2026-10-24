"""BD NET build 111: complete nested documents and binary recovery; synthetic."""
import base64
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from decoders.Python.apps.BD_NET_VPN import codec, file_decoder
from decoders.Python import xor_family
from tests.test_apna_vpn import seal, profile_seal

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT/"decoders/Python/apps/BD_NET_VPN"


def hex_seal(raw):
    key = bytes.fromhex("342550645863683e666b505d")
    return bytes(value ^ key[index%12] for index, value in enumerate(raw)).hex()


class BDNetTests(unittest.TestCase):
    def setUp(self):
        self.binary = b"proxy-prefix\0binary\xff\xfe"
        self.encrypted_binary = hex_seal(self.binary)
        self.profile = {"friendly_name": "Prueba 🛠 é", "tweak_password": "synthetic-lock",
                        "payload": hex_seal(b"G\xc1\x85T / HTTP/1.1\r\n"),
                        "sausage": self.encrypted_binary, "host": "plain.example.invalid",
                        "hwid_lock": "deadbeef", "block_rooted": True, "tweak_expiry": "2030",
                        "unknown": {"hexIdentifier": "deadbeef", "types": [False, None, 3.5]}}
        self.expected_profile = dict(self.profile, payload="GET / HTTP/1.1\r\n", sausage="proxy-prefix")
        recovery = {"path": "/sausage", "reason": "NON_UTF8_AFTER_NUL", "encoding": "base64",
                    "decodedBytesBase64": base64.b64encode(self.binary).decode(), "sourceHex": self.encrypted_binary}
        self.expected_profile["_spdecodeBinaryFields"] = [recovery]
        self.profile_wire = profile_seal(json.dumps(self.profile, ensure_ascii=False)).decode()
        self.catalog = {"Version": "test.111", "Free_servers": [{"server_name": "test", "server_host": hex_seal(b"vpn.example.invalid"), "password": "deadbeef"}],
                        "Payloads": [self.profile], "HopPayload": hex_seal(b"\xc0\xb5"),
                        "SSLPayload": hex_seal(b"A\0B"), "future": {"all": [True, None]}}
        network = dict(self.expected_profile); network.pop("_spdecodeBinaryFields")
        self.expected_catalog = dict(self.catalog, Free_servers=[{"server_name": "test", "server_host": "vpn.example.invalid", "password": "deadbeef"}],
                                     Payloads=[network], HopPayload="5", SSLPayload="A\0B")
        self.expected_catalog["_spdecodeBinaryFields"] = [{**recovery, "path": "/Payloads/0/sausage"}]
        self.catalog_wire = seal(json.dumps(self.catalog, ensure_ascii=False).encode())

    def test_whole_catalog_including_nested_fields_and_binary_tail(self):
        actual = json.loads(codec.decode_json_bytes(self.catalog_wire))
        self.assertEqual(actual, self.expected_catalog)
        recovered = actual["_spdecodeBinaryFields"][0]
        self.assertEqual(base64.b64decode(recovered["decodedBytesBase64"]), self.binary)
        self.assertEqual(codec.summary(codec.decode_json_bytes(self.catalog_wire))["binaryFieldsPreserved"], 1)

    def test_files_links_password_lock_and_unchanged_identifiers(self):
        for token in (self.profile_wire, "bdnet://"+self.profile_wire, "BDNET://"+self.profile_wire.upper()):
            actual = json.loads(file_decoder.run(token.encode()))
            self.assertEqual(actual, self.expected_profile)
            self.assertEqual(actual["hwid_lock"], "deadbeef")
            self.assertEqual(actual["tweak_password"], "synthetic-lock")
        obj = dict(self.profile, tweak_password="")
        actual = json.loads(file_decoder.run(profile_seal(json.dumps(obj, ensure_ascii=False))))
        self.assertEqual(actual["tweak_password"], "")

    def test_jni_code_units_overlong_nul_surrogates_and_legacy_utf8(self):
        self.assertEqual(codec.modified_utf8(b"\xc0\xb5\xc1\x9f\xe0\x80\xa0"), "5_ ")
        self.assertEqual(codec.modified_utf8(b"A\0B\xc0\x80C"), "A\0B\0C")
        self.assertEqual(codec.modified_utf8(b"\xed\xa0\xbd\xed\xb8\x80"), "😀")
        self.assertEqual(codec.modified_utf8("😀".encode()), "😀")
        for raw in (b"\xff", b"\xc0", b"\xc0A", b"\xed\xa0\x80", b"\xf4\x90\x80\x80"):
            with self.assertRaises(ValueError): codec.modified_utf8(raw)

    def test_invalid_fields_fail_before_nul_and_no_reserved_metadata_collision(self):
        for raw in (b"\xff\0tail", b"\xc0A", b"\xed\xa0\x80"):
            obj = dict(self.profile, payload=hex_seal(raw))
            with self.assertRaises(ValueError): file_decoder.run(profile_seal(json.dumps(obj)))
        obj = dict(self.profile, _spdecodeBinaryFields=[])
        with self.assertRaises(ValueError): file_decoder.run(profile_seal(json.dumps(obj)))

    def test_catalog_malformed_duplicate_nonfinite_and_limits(self):
        for plain in (b'{"Version":"a","Version":"b","Free_servers":[],"Payloads":[]}',
                      b'{"Version":"a","Free_servers":[],"Payloads":[],"x":NaN}',
                      b'{"Version":"a","Free_servers":[],"Payloads":[],"x":1e9999}',
                      b'{"Version":"a","Free_servers":[1],"Payloads":[]}',
                      b'{"Version":"a","Free_servers":[],"Payloads":[],"x":"\\ud800"}'):
            with self.assertRaises(ValueError): codec.decode_json_bytes(seal(plain))
        for data in (b"", b"%%%%", b"AAAA", b"x"*(codec.MAX_INPUT+1), None):
            with self.assertRaises(ValueError): codec.decode_json_bytes(data)
        for data in (b"", b"bdnet://", b"ab1", b"zz", b"ff", b"x"*(codec.MAX_INPUT+1)):
            with self.assertRaises(ValueError): codec.decode_profile_bytes(data)

    def test_actual_worker_file_text_and_catalog_are_complete(self):
        from cloud.workers.python.engine import decode_file, decode_text, decode_provider_catalog, load_file_engines, load_runtime_file_engines
        for output, expected in ((decode_file("bdnet", self.profile_wire.encode()), self.expected_profile),
                                 (decode_text("bdnet://"+self.profile_wire), self.expected_profile),
                                 (decode_provider_catalog("bd-net-vpn", self.catalog_wire), self.expected_catalog)):
            self.assertEqual(output["structuredJson"], expected)
            self.assertEqual(json.loads(output["rawText"]), expected)
            self.assertFalse(output["isPartial"])
        base = load_file_engines(); runtime = load_runtime_file_engines()
        self.assertEqual(len(base), 240); self.assertEqual(len(runtime), 252)
        self.assertTrue(base["bdnet"]["source"].endswith("/xor_family.py"))
        self.assertIn("/BD_NET_VPN/", runtime["bdnet"]["source"])
        self.assertEqual(runtime["fnf"], base["fnf"])

    def test_bot_file_text_and_legacy_generic_json(self):
        self.assertEqual(json.loads(xor_family.decode_text("bdnet://"+self.profile_wire)), self.expected_profile)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"profile.bdnet"; path.write_text(self.profile_wire)
            done = subprocess.run([sys.executable, str(ROOT/"decoders/Python/xor_family.py"), str(path)], capture_output=True, timeout=15, check=True)
            self.assertEqual(json.loads(done.stdout), self.expected_profile)
        obj = {"server": "example.invalid", "port": 443}
        self.assertEqual(json.loads(file_decoder.run(profile_seal(json.dumps(obj)))), obj)

    def test_standalone_stdlib_cli_output_permissions_summary_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); script = root/"bd_net_vpn.py"; shutil.copyfile(APP/"codec.py", script)
            source = root/"catalog.enc"; source.write_bytes(self.catalog_wire); target = root/"result.json"
            env = dict(os.environ); env.pop("PYTHONPATH", None)
            command = [sys.executable, "-S", str(script), "--input", str(source)]
            subprocess.run([*command, "--output", str(target)], check=True, capture_output=True, cwd=root, env=env, timeout=15)
            self.assertEqual(json.loads(target.read_text()), self.expected_catalog)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            again = subprocess.run([*command, "--output", str(target)], capture_output=True, cwd=root, env=env, timeout=15)
            self.assertEqual(again.returncode, 1)
            info = subprocess.run([*command, "--summary"], check=True, capture_output=True, cwd=root, env=env, timeout=15)
            self.assertEqual(json.loads(info.stdout)["payloadCount"], 1)
            self.assertNotIn(b"synthetic-lock", info.stdout)

    def test_fixed_download_status_encoding_size_and_redirects(self):
        response = MagicMock(status=200, headers={}); response.read.return_value = self.catalog_wire
        opener = MagicMock(); opener.open.return_value.__enter__.return_value = response
        with patch.object(codec, "build_opener", return_value=opener):
            self.assertEqual(codec.download(), self.catalog_wire)
            request = opener.open.call_args.args[0]
            self.assertEqual(request.full_url, "https://raw.githubusercontent.com/panigbatanc/BDNET2023/main/JSONDEC2025")
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(request.get_header("Accept-encoding"), "identity")
            self.assertEqual(request.get_header("User-agent"), "BD NET VPN/PrinceBuild111")
            self.assertEqual(opener.open.call_args.kwargs["timeout"], 25)
            response.read.assert_called_with(codec.MAX_INPUT+1)
            for status, headers, data in ((403, {}, b"x"), (200, {"Content-Encoding":"gzip"}, b"x"), (200, {}, b""), (200, {}, b"x"*(codec.MAX_INPUT+1))):
                response.status, response.headers, response.read.return_value = status, headers, data
                with self.assertRaises(ValueError): codec.download()
        with self.assertRaises(ValueError): codec._NoRedirect().redirect_request(None, None, 302, "", {}, codec.CATALOG_URL)

    @unittest.skipUnless(shutil.which("java"), "Independent JDK reference requires Java")
    def test_independent_jdk_whole_catalog_and_profile_with_raw_binary(self):
        from scripts.apk_analysis import bd_net_verify as reference
        with tempfile.TemporaryDirectory() as tmp:
            helper = (ROOT/"tests/golden/apna_oracle.java").read_text()
            helper = re.sub(r"^import[^\n]+;\n", "", helper, flags=re.MULTILINE)
            (Path(tmp)/"bd_net_oracle.java").write_text((ROOT/"tests/golden/bd_net_oracle.java").read_text()+"\n"+helper)
            for wire, profile, expected in ((self.catalog_wire, False, self.expected_catalog), (self.profile_wire.encode(), True, self.expected_profile)):
                actual, fields = reference.independent(tmp, wire, profile)
                self.assertEqual(actual, expected)
                self.assertGreater(fields, 0)


if __name__ == "__main__": unittest.main()
