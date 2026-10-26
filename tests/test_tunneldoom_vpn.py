"""TunnelDOOM full catalog parity, legacy SKS reuse, and explicit failures."""
import base64
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from decoders.Python.apps.TunnelDOOM_VPN import codec, file_decoder, server_catalog_decoder
from decoders.Python.apps.HTTP_FenixVPN import codec as sks
from scripts.apk_analysis.tunneldoom_verify import REFERENCE_FIELDS, oracle, reference

ROOT = Path(__file__).resolve().parents[1]


class TunnelDoomTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = {"Version": "synthetic-424", "ReleaseNotes": "完整 / ñ / 😀", "Servers": [
            {"Name": "all fields", "ServerPort": "22", "SSLPort": "443", "ProxyPort": "80",
             "BhttpUp": "1", "BhttpDown": "16", "FLAG": "xx", "isSSL": True,
             "isCustomServer": False, "unknown": {"keep": [None, False, 42]}}
        ], "UnknownRoot": [False, None, "keep"]}
        for i, key in enumerate(sorted(REFERENCE_FIELDS)):
            cls.expected["Servers"][0][key] = f"synthetic {i}: ñ 中 😀\r\n"
        second = copy.deepcopy(cls.expected["Servers"][0])
        second.update(Name="optional empty", ServerUser="", ServerPass="")
        cls.expected["Servers"].append(second)
        cls.encrypted = copy.deepcopy(cls.expected)
        positions = [(entry, key) for entry in cls.encrypted["Servers"]
                     for key in sorted(codec.SERVER_FIELDS) if entry[key]]
        encrypted = oracle([("field-seal", entry[key].encode()) for entry, key in positions])
        for (entry, key), value in zip(positions, encrypted, strict=True):
            entry[key] = value.decode()
        cls.plain = json.dumps(cls.encrypted, ensure_ascii=False).encode()
        cls.cipher = oracle([("seal", cls.plain)])[0]

    def test_entire_document_jca_codec_and_worker_match(self):
        expected, fields, outer = reference(self.cipher)
        self.assertEqual(fields, 24)
        self.assertEqual(expected, self.expected)
        self.assertEqual(codec.decrypt_catalog(self.cipher), outer)
        self.assertEqual(codec.decode_catalog(self.cipher), self.expected)
        self.assertEqual(json.loads(server_catalog_decoder.run(self.cipher)), self.expected)
        from cloud.workers.python.engine import decode_provider_catalog
        result = decode_provider_catalog("tunneldoom-vpn", self.cipher)
        self.assertEqual(result["structuredJson"], self.expected)
        self.assertEqual(json.loads(result["rawText"]), self.expected)
        self.assertFalse(result["isPartial"])

    def test_android_base64_bom_linewrap_and_missing_padding(self):
        wrapped = b"\xef\xbb\xbf\r\n" + b"\n".join(self.cipher[i:i+63] for i in range(0,len(self.cipher),63)) + b"\r\n"
        self.assertEqual(codec.decode_catalog(wrapped), self.expected)
        self.assertEqual(codec.decode_catalog(self.cipher.rstrip(b"=")), self.expected)

    def test_corrupt_field_is_failure_and_never_returns_partial_json(self):
        broken = copy.deepcopy(self.encrypted)
        broken["Servers"][1]["Payload"] = "not-ciphertext"
        data = oracle([("seal", json.dumps(broken).encode())])[0]
        with self.assertRaises(codec.DecodeError):
            server_catalog_decoder.run(data)

    def test_invalid_json_schema_duplicates_nonfinite_and_size_fail(self):
        for plain in [b'{}', b'{"Version":"1","Servers":[1]}',
                      b'{"Version":"1","Servers":[]}',
                      b'{"Version":"1","Servers":[{"Name":"x","ServerIP":false}]}',
                      b'{"Version":"1","Version":"2","Servers":[{"Name":"x"}]}',
                      b'{"Version":"1","Servers":[{"Name":"x"}],"bad":NaN}',
                      b'{"Version":"1","Servers":[{"Name":"x"}],"bad":1e999}']:
            data = oracle([("seal", plain)])[0]
            with self.subTest(plain=plain), self.assertRaises(codec.DecodeError):
                codec.run(data)
        for data in (b"", b"!", self.cipher[:-20], self.plain, b"a"*(codec.MAX_BYTES+1)):
            with self.assertRaises(codec.DecodeError): codec.run(data)

    def test_depth_and_output_limits(self):
        obj = copy.deepcopy(self.encrypted)
        deep = obj
        for _ in range(66):
            deep["deep"] = {}; deep = deep["deep"]
        data = oracle([("seal", json.dumps(obj).encode())])[0]
        with self.assertRaises(codec.DecodeError): codec.run(data)
        with patch.object(codec, "MAX_BYTES", 10):
            with self.assertRaises(codec.DecodeError): codec.render(self.expected)

    def test_sks_reuses_canonical_gcm_des_and_preserves_historical_socksip(self):
        from cloud.workers.python.engine import decode_file
        xml = b'<?xml version="1.0" encoding="UTF-8"?><properties><entry key="file.proteger">1</entry><entry key="password">synthetic-only</entry><entry key="dup">a</entry><entry key="dup">b</entry></properties>'
        incoming = ''.join(mode+'\t'+base64.b64encode(xml).decode()+'\n'
                           for mode in ("profile-encrypt", "des-encrypt"))
        r = subprocess.run(["java", str(ROOT/"tests/golden/fenix_oracle.java")], input=incoming,
                           text=True, capture_output=True, check=True, timeout=30)
        gcm, des64 = [base64.b64decode(line) for line in r.stdout.splitlines()]
        for data in (gcm, base64.b64decode(des64)):
            expected = sks.decode_profile(data)
            self.assertEqual(json.loads(file_decoder.run(data)), expected)
            self.assertEqual(decode_file("sks", data)["structuredJson"], expected)
            self.assertEqual(expected["raw_xml"], xml.decode())
        broken = bytearray(gcm); broken[-4] = ord("A") if broken[-4] != ord("A") else ord("B")
        with patch.object(sks.DES, "new", side_effect=AssertionError("GCM never retries DES")):
            with self.assertRaises(sks.DecodeError): file_decoder.run(bytes(broken))
        from cloud.workers.python.engine import load_file_engines, load_runtime_file_engines
        self.assertEqual(len(load_file_engines()), 240)
        self.assertEqual(len(load_runtime_file_engines()), 254)
        self.assertTrue(load_file_engines()["sks"]["source"].endswith("/sks.js"))

    def test_fixed_cli_download_and_redirect_rejection(self):
        class Response:
            status = 200
            headers = {}
            def __enter__(inner): return inner
            def __exit__(inner, *args): pass
            def read(inner, size): return self.cipher[:size]
        class Opener:
            def open(inner, request, timeout):
                self.assertEqual(request.full_url, "https://panel.tunneldoom.space/config.json")
                self.assertEqual(timeout, 25)
                return Response()
        with patch.object(server_catalog_decoder, "build_opener", return_value=Opener()):
            self.assertEqual(server_catalog_decoder.download(), self.cipher)
        with self.assertRaises(codec.DecodeError):
            server_catalog_decoder._NoRedirect().redirect_request(None,None,302,"",{},"https://else.invalid")

    def test_cli_private_output_no_overwrite_and_no_errors_leak(self):
        script = ROOT/"decoders/Python/apps/TunnelDOOM_VPN/server_catalog_decoder.py"
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder)/"catalog.enc"; source.write_bytes(self.cipher)
            target = Path(folder)/"result.json"
            cmd = [sys.executable, str(script), str(source), "-o", str(target)]
            result = subprocess.run(cmd, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(target.read_bytes()), self.expected)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(subprocess.run(cmd,capture_output=True,timeout=20).returncode,1)
            source.write_bytes(b"private-input-marker")
            result = subprocess.run([sys.executable,str(script),str(source)],capture_output=True,timeout=20)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b"")
            self.assertNotIn(b"private-input-marker", result.stderr)


if __name__ == "__main__": unittest.main()
