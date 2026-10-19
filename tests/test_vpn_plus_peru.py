"""VPN PLUS PERÚ reader; immutable independent JCE vectors, no real credentials."""
import base64
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from decoders.Python import vpn_plus_peru as vpn

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / "tests/golden/vpn_plus_peru_vectors.json").read_text())


class VpnPlusPeruTests(unittest.TestCase):
    def test_independent_jce_versions_preserve_all_fields(self):
        for vector in FIXTURE["vectors"]:
            with self.subTest(version=vector["version"]):
                self.assertEqual(vpn.decode(vector["data"]), FIXTURE["expected"])
                self.assertEqual(json.loads(vpn.run(vector["data"].encode())), FIXTURE["expected"])

    def test_bom_whitespace_and_base64_lines(self):
        for vector in FIXTURE["vectors"]:
            s = vector["data"]
            offset = 5 if vector["version"] > 1 else 0
            wrapped = s[:offset] + "\r\n".join(s[i:i+64] for i in range(offset, len(s), 64))
            self.assertEqual(vpn.decode(("\ufeff \n" + wrapped + "\n").encode()), FIXTURE["expected"])

    def test_akn2_akn3_authenticate_salt_iv_ciphertext_and_tag(self):
        for vector in FIXTURE["vectors"][1:]:
            blob = base64.b64decode(vector["data"][5:])
            for index in [0, 15, 16, 31, 32, len(blob)-33, len(blob)-32, len(blob)-1]:
                changed = bytearray(blob)
                changed[index] ^= 1
                with self.subTest(version=vector["version"], index=index):
                    data = vector["data"][:5] + base64.b64encode(changed).decode()
                    with patch.object(vpn.AES, "new", side_effect=AssertionError("must authenticate first")):
                        with self.assertRaises(vpn.DecodeError) as ctx:
                            vpn.decode(data)
                        self.assertEqual(ctx.exception.code, "AUTH_FAILED")
                    self.assertIsNone(vpn.run(data))

    def test_switching_version_or_using_raw_latin1_password_fails_auth(self):
        data = FIXTURE["vectors"][2]["data"]
        for s in ["AKN2:" + data[5:], "AKN3:" + FIXTURE["vectors"][1]["data"][5:]]:
            self.assertIsNone(vpn.run(s))
        with patch.object(vpn, "_password", return_value=vpn.V3_BASE):
            self.assertIsNone(vpn.run(data))

    def test_bad_prefix_base64_input_and_lengths(self):
        for data in [None, [], 1, b"", b"\xff", "AKN4:AAAA", "AKN1:AAAA", "AKN3:",
                     "!bad!", "____", "AKN2:AAAA", base64.b64encode(b"x"*17),
                     "AKN3:" + base64.b64encode(b"x"*81).decode()]:
            with self.subTest(data=type(data).__name__):
                self.assertIsNone(vpn.run(data))

    def test_plain_json_import_and_one_thousand_records_are_not_capped(self):
        doc = {"servers": [{"id": i, "unknown": {"keep": True}} for i in range(1000)], "version": "synthetic"}
        raw = json.dumps(doc)
        self.assertEqual(vpn.decode(raw), doc)
        self.assertEqual(len(json.loads(vpn.run(raw))["servers"]), 1000)

    def test_invalid_json_unicode_and_structure_limits(self):
        for text in ['{"x":1,"x":2}', '{"x":NaN}', '{"x":1e9999}', '{"x":"\\ud800"}',
                     '{"\\ud800":1}', '{bad}', '{"x":']:
            self.assertIsNone(vpn.run(text))
        with patch.object(vpn, "MAX_DEPTH", 2):
            self.assertIsNone(vpn.run('{"a":{"b":{"c":1}}}'))
        with patch.object(vpn, "MAX_NODES", 3):
            self.assertIsNone(vpn.run('{"a":[1,2,3]}'))
        with self.assertRaises(vpn.DecodeError) as ctx:
            vpn._document("[]")
        self.assertEqual(ctx.exception.code, "WRONG_DOCUMENT")

    def test_byte_and_utf8_size_limits(self):
        with patch.object(vpn, "MAX_INPUT_BYTES", 10):
            for s in [b"x"*11, "x"*11, "日"*5]:
                with self.assertRaises(vpn.DecodeError) as ctx:
                    vpn.decode(s)
                self.assertEqual(ctx.exception.code, "SIZE_LIMIT")

    def test_decode_is_offline(self):
        with patch.object(vpn, "fetch_catalog", side_effect=AssertionError("unexpected network")):
            self.assertEqual(vpn.decode(FIXTURE["vectors"][2]["data"]), FIXTURE["expected"])

    def test_standalone_cli_with_only_script_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "vpn_plus_peru.py"
            script.write_bytes((ROOT / "decoders/Python/apps/VPN_PLUS_PERU/vpn_plus_peru.py").read_bytes())
            source = root / "test config.gol"
            source.write_text(FIXTURE["vectors"][2]["data"])
            proc = subprocess.run([sys.executable, str(script), str(source)], cwd=root,
                                  capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(proc.stdout), FIXTURE["expected"])
            self.assertEqual(proc.stderr, "")

    def test_cli_url_download_decode_and_save(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "decoded.json"
            with patch.object(vpn, "fetch_catalog", return_value=FIXTURE["vectors"][2]["data"].encode()) as fetch:
                with contextlib.redirect_stdout(io.StringIO()) as stdout:
                    self.assertEqual(vpn.main(["--url", "https://example.invalid/config.gol", "-o", str(output)]), 0)
                fetch.assert_called_once_with("https://example.invalid/config.gol")
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(json.loads(output.read_text()), FIXTURE["expected"])

    def test_cli_failure_no_partial_output_and_no_implicit_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, output = Path(tmp)/"bad.gol", Path(tmp)/"output.json"
            source.write_text("AKN3:bad")
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(vpn.main([str(source), "-o", str(output)]), 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("error", json.loads(stderr.getvalue()))
            self.assertFalse(output.exists())
            with contextlib.redirect_stderr(io.StringIO()), patch.object(vpn, "fetch_catalog") as fetch:
                for args in [[], ["--url"], [str(source), "--url", "https://example.invalid"]]:
                    with self.assertRaises(SystemExit) as ctx:
                        vpn.main(args)
                    self.assertEqual(ctx.exception.code, 2)
                fetch.assert_not_called()
                self.assertEqual(vpn.main([str(Path(tmp)/"missing")]), 2)

    def test_download_validates_url_and_bounds_response(self):
        for url in ["http://example.invalid", "file:///etc/passwd", "https://a:b@example.invalid",
                    "https:///missing", "https://example.invalid/#fragment"]:
            with patch.object(vpn, "build_opener") as opener:
                with self.assertRaises(vpn.DecodeError):
                    vpn.fetch_catalog(url)
                opener.assert_not_called()
        response = MagicMock()
        response.read.return_value = b"x"*11
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with patch.object(vpn, "build_opener", return_value=opener), patch.object(vpn, "MAX_INPUT_BYTES", 10):
            with self.assertRaises(vpn.DecodeError) as ctx:
                vpn.fetch_catalog("https://example.invalid/config.gol")
            self.assertEqual(ctx.exception.code, "SIZE_LIMIT")
            response.read.assert_called_once_with(11)
            self.assertEqual(opener.open.call_args.kwargs["timeout"], 20)
        self.assertIsNone(vpn._NoRedirect().redirect_request(None, None, 302, "", {}, "http://example.invalid"))
        with patch.object(vpn, "build_opener", side_effect=OSError("private detail")):
            with self.assertRaises(vpn.DecodeError) as ctx:
                vpn.fetch_catalog("https://example.invalid")
            self.assertNotIn("private detail", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
