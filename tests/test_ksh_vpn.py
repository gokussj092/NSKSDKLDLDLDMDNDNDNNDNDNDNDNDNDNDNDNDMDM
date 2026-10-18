"""KSH catalog tests; frozen golden generated independently with cryptography AESGCM.

Only synthetic credentials and reserved .invalid domains are used.
"""
from __future__ import annotations

import base64
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from Crypto.Cipher import AES
from decoders.Python import ksh_vpn as ksh

ROOT = Path(__file__).resolve().parents[1]
# Independent producer used AESGCM.encrypt(nonce, UTF8(JSON), None).
GOLDEN = 'AAECAwQFBgcICQoLTt+ULJoUctM9zDwSuczK8RcaV6ofsUGNbE1prmb+mJoAYLjrCSk9PbCfOvx5IY4c/U9gjWGTSDl4MfNEh59s839H4Fx5bMXauftCSo9CqRw5nT/0hFqkvq+Pr6uHKq/pM91ayEqfrQgso2N2XFeauUHlqgmH+dXQHYezthrwAILqrmbMEOh2fsxjZET1nHSJWj4beGzd/dRiW7MWgrTX3SjojKAWGgY5spuw6puBN4soAOyaWP9JOhu9xoWUuBK1gd8pNV+uxKjqXZiuwRhKMFpQV1VIaQi0RTIB0p9QHVyO3OO5+nZ9RmPHtvG1nCe+MddlxFemJ5uVz/jAXjGw8ONQ0JgziIuxVBzLONv4/6EkYL+MX4Oy+m3at2V9DW4nB+h9eWvxMPzU7Xr6kGrT+5Fmxv5T5u0oJ2U8O9EUyaFLFxRj+OMv07I8NtGm5uXDRAk51aWq6fqSar2L55rjkBIUEXCdmo3w/2Li90DeQL3nIfl4v5l8/gsvs4gXB3CCU8Us4dRhXUBp7i/DSNiro7rS2LV2HoOuDZeHXf8qDuCgN+PF8ju656R2/DxgTrscKYYnWiIcjjYAqwo5gwEbGyOob3N0zSKdJk8KfrCfkdC42LqFo7JsXpeuoFaIwaktzimMsMPerAr3PuHx3VWKnJclNLTMtHg='
EXPECTED = {'version': 1, 'servers': [{'id': 'synthetic-1', 'name': 'Prueba 日本語', 'host': 'vpn.example.invalid', 'port': 443, 'active': True, 'isPremium': False, 'accessUrl': 'vless://00000000-0000-0000-0000-000000000001@vpn.example.invalid:443?security=tls#Test', 'sshUsername': 'demo', 'sshPassword': 'synthetic-only', 'nameserver': 'dns.example.invalid', 'dnsttPubkey': 'fictitious-key', 'unknown': {'list': [None, 0, False, {'payload': 'GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n'}]}}], 'futureField': {'keep': True}}


def seal(plain: bytes, *, key: bytes = ksh.CATALOG_KEY, aad: bytes = b"") -> str:
    cipher = AES.new(key, AES.MODE_GCM, nonce=bytes(range(12)))
    cipher.update(aad)
    body, tag = cipher.encrypt_and_digest(plain)
    return base64.b64encode(bytes(range(12)) + body + tag).decode()


class KshVpnTests(unittest.TestCase):
    def assert_error(self, data, code):
        with self.assertRaises(ksh.DecodeError) as ctx:
            ksh.decode(data)
        self.assertEqual(ctx.exception.code, code)
        self.assertIsNone(ksh.run(data))

    def test_independent_golden_envelope_and_complete_unknown_fields(self):
        envelope = json.dumps({"enc": GOLDEN, "transportMetadata": 123}).encode()
        self.assertEqual(ksh.decode(envelope), EXPECTED)
        self.assertEqual(json.loads(ksh.run(envelope)), EXPECTED)

    def test_base64_bom_and_wrapping(self):
        wrapped = "﻿  " + "\r\n".join(GOLDEN[n:n+64] for n in range(0, len(GOLDEN), 64))
        self.assertEqual(ksh.decode(wrapped.encode()), EXPECTED)
        self.assertEqual(ksh.decode(wrapped), EXPECTED)

    def test_tampering_nonce_ciphertext_or_tag_never_returns_plaintext(self):
        blob = base64.b64decode(GOLDEN)
        for index in [0, 11, 12, 40, len(blob)-16, len(blob)-1]:
            with self.subTest(index=index):
                corrupt = bytearray(blob)
                corrupt[index] ^= 1
                self.assert_error(base64.b64encode(corrupt), "AUTH_FAILED")

    def test_different_key_or_aad_is_rejected(self):
        plain = b'{"servers":[]}'
        self.assert_error(seal(plain, key=b"x"*32), "AUTH_FAILED")
        self.assert_error(seal(plain, aad=b"unexpected"), "AUTH_FAILED")

    def test_invalid_base64_or_envelope(self):
        for data in [b"", b"\xff", b"!bad!", GOLDEN[:-1], "____", "{}",
                     '{"enc":null}', '{"enc":1}', '{"enc":""}',
                     '{"enc":"'+GOLDEN+'","enc":"'+GOLDEN+'"}',
                     b"{not-json", None, 1, []]:
            with self.subTest(data_type=type(data).__name__):
                self.assertIsNone(ksh.run(data))

    def test_truncated_binary_is_rejected(self):
        for length in [1, 11, 12, 27]:
            self.assert_error(base64.b64encode(b"x"*length), "TRUNCATED")

    def test_authenticated_invalid_utf8_or_json(self):
        self.assert_error(seal(b"\xff"), "INVALID_PLAINTEXT")
        self.assert_error(seal(b"not json"), "INVALID_JSON")
        self.assert_error(seal(b'{"servers":[],"servers":[]}'), "INVALID_JSON")
        self.assert_error(seal(b'{"servers":[],"value":NaN}'), "INVALID_JSON")
        self.assert_error(seal(b'{"servers":[],"value":1e9999}'), "INVALID_JSON")
        self.assert_error(seal(b'{"servers":[],"bad":"\\ud800"}'), "INVALID_JSON")
        self.assert_error(seal(b'{"servers":[],"\\ud800":0}'), "INVALID_JSON")

    def test_authenticated_wrong_document(self):
        for plain in [b"[]", b"null", b"1", b"{}", b'{"servers":{}}', b'{"servers":[1]}']:
            with self.subTest(plain=plain):
                self.assert_error(seal(plain), "WRONG_DOCUMENT")

    def test_empty_catalog_is_valid_and_preserves_metadata(self):
        self.assertEqual(ksh.decode(seal(b'{"servers":[],"v":2}')), {"servers": [], "v": 2})

    def test_size_limit_on_bytes_text_and_utf8_size(self):
        with patch.object(ksh, "MAX_INPUT_BYTES", 10):
            for data in [b"x"*11, "x"*11, "日"*5]:
                self.assert_error(data, "SIZE_LIMIT")

    def test_structure_depth_and_node_limits(self):
        with patch.object(ksh, "MAX_DEPTH", 2):
            self.assert_error(GOLDEN, "STRUCTURE_LIMIT")
        with patch.object(ksh, "MAX_NODES", 5):
            self.assert_error(GOLDEN, "STRUCTURE_LIMIT")

    def test_decoding_never_fetches(self):
        with patch.object(ksh, "fetch_catalog", side_effect=AssertionError("unexpected network")):
            self.assertEqual(ksh.decode(GOLDEN), EXPECTED)

    def test_cli_file_and_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)/"encrypted catalog.json"
            output = Path(tmp)/"decoded.json"
            source.write_text(json.dumps({"enc": GOLDEN}))
            proc = subprocess.run([sys.executable, str(ROOT/"decoders/Python/ksh_vpn.py"),
                                   str(source), "-o", str(output)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, "")
            self.assertEqual(proc.stderr, "")
            self.assertEqual(json.loads(output.read_text()), EXPECTED)

    def test_cli_failure_has_no_plaintext_or_output_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)/"bad.json"
            output = Path(tmp)/"decoded.json"
            source.write_text("not encrypted!")
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = ksh.main([str(source), "-o", str(output)])
            self.assertEqual(result, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(json.loads(stderr.getvalue())["error"], "FORMAT_ERROR")
            self.assertFalse(output.exists())

    def test_cli_io_and_usage_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(ksh.main([str(Path(tmp)/"missing")]), 2)
                for args in [[], ["file.json", "--url"]]:
                    with self.assertRaises(SystemExit) as ctx:
                        ksh.main(args)
                    self.assertEqual(ctx.exception.code, 2)

    def test_cli_explicit_download(self):
        with patch.object(ksh, "fetch_catalog", return_value=json.dumps({"enc": GOLDEN}).encode()) as fetch:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(ksh.main(["--url"]), 0)
            fetch.assert_called_once_with(ksh.CATALOG_URL)
            self.assertEqual(json.loads(stdout.getvalue()), EXPECTED)

    def test_download_requires_https_without_credentials(self):
        for url in ["http://example.invalid", "file:///etc/passwd", "https://a:b@example.invalid",
                    "https:///nohost", "https://example.invalid/#fragment"]:
            with self.subTest(url=url), patch.object(ksh, "build_opener") as opener:
                with self.assertRaises(ksh.DecodeError) as ctx:
                    ksh.fetch_catalog(url)
                self.assertEqual(ctx.exception.code, "DOWNLOAD_FAILED")
                opener.assert_not_called()

    def test_download_is_bounded_and_errors_are_sanitized(self):
        response = MagicMock()
        response.read.return_value = b"x"*11
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with patch.object(ksh, "build_opener", return_value=opener), patch.object(ksh, "MAX_INPUT_BYTES", 10):
            with self.assertRaises(ksh.DecodeError) as ctx:
                ksh.fetch_catalog(ksh.CATALOG_URL)
            self.assertEqual(ctx.exception.code, "SIZE_LIMIT")
            response.read.assert_called_once_with(11)
            self.assertEqual(opener.open.call_args.kwargs["timeout"], 20)
        with patch.object(ksh, "build_opener", side_effect=OSError("sensitive transport detail")):
            with self.assertRaises(ksh.DecodeError) as ctx:
                ksh.fetch_catalog(ksh.CATALOG_URL)
            self.assertNotIn("sensitive", str(ctx.exception))
        self.assertIsNone(ksh._NoRedirect().redirect_request(None, None, 302, "", {}, "http://example.invalid"))


if __name__ == "__main__":
    unittest.main()
