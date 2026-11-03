"""Ultra build59 catalog framing, complete independent JSON and Cloud isolation."""
import base64
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from decoders.Python.apps.Ultra_Tunnel import codec, server_catalog_decoder as catalog

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "decoders/Python/apps/Ultra_Tunnel"
V = json.loads((ROOT / "tests/golden/ultra_tunnel_vectors.json").read_text(encoding="utf-8"))


class UltraTunnelTests(unittest.TestCase):
    def test_independent_jca_bundled_remote_plain_and_all_inner_fields(self):
        for case in V["documents"]:
            with self.subTest(case=case["mode"]):
                self.assertEqual(json.loads(catalog.run(case["wire"].encode())), case["expected"])
        sample = V["documents"][0]["expected"]
        self.assertEqual(sample["Networks"][0]["URI"], True)
        self.assertEqual(sample["Networks"][0]["future"]["values"], [False, None, "keep"])
        self.assertNotEqual(sample["Networks"][0]["Info"], sample["Networks"][0]["Payload"])
        self.assertEqual(sample["Servers"][0], sample["Servers"][1])
        self.assertEqual(sample["DefOVPNPass"], "")

    def test_argon2_matches_independent_libsodium(self):
        from argon2.low_level import Type, hash_secret_raw
        value = V["kdf"]
        self.assertEqual(hash_secret_raw(value["password"].encode(), bytes.fromhex(value["saltHex"]),
                                        3, 8192, 1, 32, Type.ID, version=19).hex(), value["keyHex"])

    def test_outer_and_inner_tags_reject_entire_document(self):
        for case in V["documents"]:
            if case["mode"] == "plain":
                continue
            text = case["wire"]
            if case["mode"] == "remote":
                text = text[:3] + text[4:]
            raw = bytearray(base64.b64decode(text)); raw[-1] ^= 1
            text = base64.b64encode(raw).decode()
            if case["mode"] == "remote":
                text = text[:3] + "Q" + text[3:]
            with self.assertRaises(codec.DecodeError):
                catalog.run(text.encode())
        doc = json.loads(V["documents"][0]["wire"])
        raw = bytearray(base64.b64decode(doc["Networks"][0]["Payload"])); raw[-1] ^= 1
        doc["Networks"][0]["Payload"] = base64.b64encode(raw).decode()
        with self.assertRaises(codec.DecodeError):
            catalog.run(json.dumps(doc).encode())

    def test_bounds_schema_duplicates_surrogates_and_finite_numbers(self):
        valid = json.loads(V["documents"][0]["wire"])
        cases = [b"", b"<html>not a catalog</html>", b"x"*(codec.MAX_BYTES+1),
                 b'{"Version":"1","Version":"2"}', b'{"Version":NaN}',
                 json.dumps({**valid, "Servers": []}).encode(),
                 json.dumps({**valid, "Networks": [False]}).encode(),
                 json.dumps({**valid, "Version": 59}).encode(),
                 json.dumps({**valid, "unknown": "\ud800"}).encode()]
        for value in cases:
            with self.subTest(size=len(value)), self.assertRaises(ValueError):
                catalog.run(value)
        with patch.object(codec, "MAX_FIELDS", 0), self.assertRaises(codec.DecodeError):
            catalog.run(json.dumps(valid).encode())

    def test_optional_scalars_plain_fields_and_unknown_ciphertext_are_preserved(self):
        doc = json.loads(V["documents"][0]["wire"])
        doc["Servers"][0]["OVPNUser"] = None
        doc["Servers"][0]["OVPNPass"] = "literal user text"
        doc["Networks"][0]["SNI"] = False
        out = json.loads(catalog.run(json.dumps(doc).encode()))
        self.assertIsNone(out["Servers"][0]["OVPNUser"])
        self.assertEqual(out["Servers"][0]["OVPNPass"], "literal user text")
        self.assertIs(out["Networks"][0]["SNI"], False)
        self.assertEqual(out["unknown"], doc["unknown"])

    def test_worker_returns_complete_provider_document_and_rejects_tampering(self):
        from cloud.workers.python.engine import decode_provider_catalog, DecodeFailure
        case = next(case for case in V["documents"] if case["mode"] == "remote")
        result = decode_provider_catalog("ultra-tunnel", case["wire"].encode())
        self.assertEqual(result["structuredJson"], case["expected"])
        self.assertEqual(json.loads(result["rawText"]), case["expected"])
        self.assertFalse(result["isPartial"])
        self.assertFalse(result["exporterCertified"])
        with self.assertRaises(DecodeFailure):
            decode_provider_catalog("ultra-tunnel", b"<html/>")

    def test_fixed_get_headers_bounds_redirects_and_sanitized_failures(self):
        case = next(case for case in V["documents"] if case["mode"] == "remote")
        body = case["wire"].encode()
        class Reply:
            status = 200
            headers = {}
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, limit):
                self.limit = limit
                return body
        class Opener:
            def open(self, request, timeout):
                self.request, self.timeout = request, timeout
                return reply
        opener, reply = Opener(), Reply()
        with patch.object(catalog, "build_opener", return_value=opener):
            self.assertEqual(catalog.download(), body)
            self.assertEqual(opener.request.full_url, catalog.SOURCE)
            self.assertEqual(opener.request.get_method(), "GET")
            self.assertEqual(opener.request.get_header("User-agent"), "Ultra Tunnel")
            self.assertIsNone(opener.request.data)
            self.assertIsNone(opener.request.get_header("Authorization"))
            self.assertEqual(reply.limit, codec.MAX_BYTES+1)
            for bad in [b"<html/>", b"{}", b"", b"x"*(codec.MAX_BYTES+1)]:
                body = bad
                with self.assertRaises(codec.DecodeError): catalog.download()
            body = case["wire"].encode()
            reply.headers = {"Content-Encoding": "gzip"}
            with self.assertRaises(codec.DecodeError): catalog.download()
            opener.open = lambda *args, **kwargs: (_ for _ in ()).throw(HTTPError(catalog.SOURCE, 403, "private-sentinel", {}, None))
            with self.assertRaises(codec.DecodeError) as error: catalog.download()
            self.assertNotIn("private-sentinel", str(error.exception))
        with self.assertRaises(codec.DecodeError):
            catalog._NoRedirect().redirect_request(None, None, 302, None, None, None)

    def test_cli_outside_checkout_and_invalid_input_has_no_stdout(self):
        case = next(case for case in V["documents"] if case["mode"] == "remote")
        command = [sys.executable, str(APP/"server_catalog_decoder.py"), "--stdin"]
        result = subprocess.run(command, input=case["wire"].encode(), capture_output=True, cwd="/tmp", timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(json.loads(result.stdout), case["expected"])
        result = subprocess.run(command, input=b"<html>private-sentinel</html>", capture_output=True, cwd="/tmp", timeout=20)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(b"private-sentinel", result.stderr)


if __name__ == "__main__":
    unittest.main()
