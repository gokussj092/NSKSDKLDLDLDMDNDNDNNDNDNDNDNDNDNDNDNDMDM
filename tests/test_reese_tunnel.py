"""REESE .RT parity against frozen OpenJDK/JCE encryptor vectors.

All fixtures are synthetic. No actual user export or credentials are committed.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

from Crypto.Cipher import AES
from decoders.Python import reese_tunnel as rt

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / "tests/golden/reese_vectors.json").read_text("utf-8"))
CASES = {case["name"]: case for case in FIXTURE["cases"]}
# Golden ciphertext still contains bannerImage. Only this output expectation
# removes the display-only image, preserving cryptographic test vectors.
EXPECTED = json.loads(json.dumps(FIXTURE["expected"]))
def strip_banner_images(node):
    if isinstance(node, dict):
        node.pop("bannerImage", None)
        for value in node.values():
            strip_banner_images(value)
    elif isinstance(node, list):
        for value in node:
            strip_banner_images(value)
strip_banner_images(EXPECTED)


def raw(name):
    return base64.b64decode(CASES[name]["data"])


def options(name):
    return {key: CASES[name][key] for key in ("hwid", "password")}


def seal_body(body):
    header = rt.MAGIC + b"\xc4\x00" + bytes(range(16)) + bytes(range(16, 28))
    key = hashlib.pbkdf2_hmac("sha256", b"REESE-CUSTOM/RSE5||", header[6:22], 32768, 32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=header[22:34])
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(body)
    return header + ciphertext + tag


def seal_json(plain):
    compressor = zlib.compressobj(level=1, wbits=-15)
    packed = compressor.compress(plain) + compressor.flush()
    return seal_body(b"\0" + b"p" * 16 + struct.pack(">I", len(packed)) + packed + b"tail")


class ReeseTunnelTests(unittest.TestCase):
    def assert_error(self, data, code, **kwargs):
        with self.assertRaises(rt.DecodeError) as ctx:
            rt.decode(data, **kwargs)
        self.assertEqual(ctx.exception.code, code)
        self.assertIsNone(rt.run(data, **kwargs))

    def test_all_16_independent_java_vectors_preserve_json_without_banner(self):
        self.assertEqual(len(CASES), 16)
        for name, case in CASES.items():
            with self.subTest(name=name):
                audit = {}
                self.assertEqual(rt.decode(raw(name), audit=audit, **options(name)), EXPECTED)
                self.assertEqual(audit["format"], case["format"])
                self.assertTrue(audit["authenticated"])
                self.assertEqual(json.loads(rt.run(raw(name), **options(name))), EXPECTED)

    def test_base64_wrapping_bom_and_legacy_armor(self):
        for name in ["rse5-c4-flags4", "rse2-protected", "rse4-open"]:
            encoded = CASES[name]["data"]
            wrapped = "\ufeff-----BEGIN REESE CONFIG-----\nProtected: yes\n\n" + "\r\n".join(
                encoded[n:n + 70] for n in range(0, len(encoded), 70)) + "\n-----END REESE CONFIG-----"
            self.assertEqual(rt.decode(wrapped.encode(), **options(name)), EXPECTED)
            self.assertEqual(rt.decode(encoded.rstrip("="), **options(name)), EXPECTED)

    def test_ciphertext_and_tag_tampering_all_versions(self):
        for name in CASES:
            with self.subTest(name=name):
                data = bytearray(raw(name))
                data[-1] ^= 1
                self.assert_error(bytes(data), "AUTH_FAILED", **options(name))

    def test_current_header_nonce_and_ciphertext_are_authenticated(self):
        data = raw("rse5-c4-flags4")
        for offset in [6, 21, 22, 33, 34, 55]:
            with self.subTest(offset=offset):
                mutated = bytearray(data)
                mutated[offset] ^= 1
                self.assert_error(bytes(mutated), "AUTH_FAILED")

    def test_legacy_hmac_is_verified_before_cbc(self):
        for name in ["rse1-open", "rse2-open", "rse3-open"]:
            data = bytearray(raw(name))
            data[80] ^= 1
            with patch.object(rt, "_cbc", side_effect=AssertionError("CBC must not run")):
                self.assert_error(bytes(data), "AUTH_FAILED")

    def test_current_password_hwid_and_both_require_credentials(self):
        self.assert_error(raw("rse5-c4-flags1"), "HWID_REQUIRED")
        self.assert_error(raw("rse5-c4-flags2"), "PASSWORD_REQUIRED")
        self.assert_error(raw("rse5-c4-flags3"), "HWID_REQUIRED")
        self.assert_error(raw("rse5-c4-flags3"), "PASSWORD_REQUIRED", hwid=CASES["rse5-c4-flags3"]["hwid"])

    def test_wrong_credentials_and_public_signer_fail_authentication(self):
        for name in ["rse1-protected", "rse3-protected", "rse4-protected", "rse5-c3-protected", "rse5-c4-flags7"]:
            values = options(name)
            values["password"] = "incorrect"
            self.assert_error(raw(name), "AUTH_FAILED", **values)
        self.assert_error(raw("rse5-c4-flags4"), "AUTH_FAILED", signer_sha256="0" * 64)
        self.assert_error(raw("rse5-c4-flags4"), "SIGNER_REQUIRED", signer_sha256="not-a-certificate-hash")

    def test_normalization_and_unused_credentials(self):
        self.assertEqual(rt._trim("\x85value\x85"), "\x85value\x85")
        values = options("rse5-c4-flags7")
        values["password"] = " \t" + values["password"] + "\n"
        values["hwid"] = " \t" + values["hwid"].lower() + "\n"
        self.assertEqual(rt.decode(raw("rse5-c4-flags7"), signer_sha256=rt.APK_SIGNER_SHA256.lower(), **values), EXPECTED)
        self.assertEqual(rt.decode(raw("rse5-c4-flags0"), password="unused", hwid="unused"), EXPECTED)

    def test_unknown_version_flags_and_truncated_headers(self):
        data = bytearray(raw("rse5-c4-flags0"))
        data[4] = 0xC5
        self.assert_error(bytes(data), "UNSUPPORTED_VERSION")
        data[4], data[5] = 0xC4, 0x80
        self.assert_error(bytes(data), "UNSUPPORTED_FLAGS")
        for size in [4, 5, 6, 22, 34, 49]:
            self.assert_error(raw("rse5-c4-flags0")[:size], "TRUNCATED")

    def test_malformed_input_is_rejected(self):
        for value in [None, 1, [], b"", b"\xff", "not a configuration!", "AAAAA", "----", "e30="]:
            with self.subTest(kind=type(value).__name__):
                self.assertIsNone(rt.run(value))
        for name in ["rse1-open", "rse2-open", "rse3-open", "rse4-open"]:
            self.assert_error(raw(name)[:20], "TRUNCATED")

    def test_authenticated_random_padding_and_deflate_validation(self):
        for body in [b"", b"\xff", b"\0" + b"p" * 16,
                     b"\0" + b"p" * 16 + struct.pack(">i", -1),
                     b"\0" + b"p" * 16 + struct.pack(">i", 100) + b"short"]:
            self.assert_error(seal_body(body), "INVALID_PADDING")
        self.assert_error(seal_body(b"\0" + b"p" * 16 + struct.pack(">I", 4) + b"junk"), "INVALID_DEFLATE")

    def test_authenticated_invalid_json_and_wrong_documents(self):
        for plain in [b"not json", b"\xff", b'{"meta":{},"config":{},"config":{}}',
                      b'{"meta":{},"config":{"profileName":"x","number":NaN}}',
                      b'{"meta":{},"config":{"profileName":"x","number":1e9999}}',
                      br'{"meta":{},"config":{"profileName":"\ud800"}}']:
            self.assert_error(seal_json(plain), "INVALID_JSON")
        for plain in [b"[]", b"null", b"{}", b'{"config":{}}', b'{"meta":{},"config":{}}', b'{"profileName":"bare"}']:
            self.assert_error(seal_json(plain), "WRONG_DOCUMENT")

    def test_plain_json_is_preserved_and_is_not_claimed_authenticated(self):
        data = json.dumps(EXPECTED["config"], ensure_ascii=False)
        audit = {}
        self.assertEqual(rt.decode(data, audit=audit), EXPECTED["config"])
        self.assertFalse(audit["authenticated"])

    def test_device_local_vault_is_reported_instead_of_partial_success(self):
        data = json.loads(json.dumps(EXPECTED))
        data["config"]["vault"] = "synthetic-device-sealed-content"
        self.assert_error(seal_json(json.dumps(data).encode()), "DEVICE_VAULT_REQUIRED")

    def test_input_decompression_structure_and_credential_limits(self):
        with patch.object(rt, "MAX_INPUT_BYTES", 10):
            self.assert_error(b"x" * 11, "SIZE_LIMIT")
            self.assert_error("日" * 5, "SIZE_LIMIT")
        with patch.object(rt, "MAX_JSON_BYTES", 20):
            self.assert_error(raw("rse5-c4-flags0"), "SIZE_LIMIT")
        with patch.object(rt, "MAX_DEPTH", 2):
            self.assert_error(raw("rse5-c4-flags0"), "STRUCTURE_LIMIT")
        with patch.object(rt, "MAX_NODES", 4):
            self.assert_error(raw("rse5-c4-flags0"), "STRUCTURE_LIMIT")
        self.assert_error(raw("rse5-c4-flags0"), "CREDENTIAL_FORMAT", password="x" * 4097)
        self.assert_error(raw("rse5-c4-flags0"), "CREDENTIAL_FORMAT", hwid=None)

    def test_legacy_length_and_work_limits(self):
        for name, offset in [("rse1-open", 52), ("rse2-open", 68), ("rse3-open", 68), ("rse4-open", 36)]:
            data = bytearray(raw(name))
            struct.pack_into(">i", data, offset, -1)
            self.assert_error(bytes(data), "TRUNCATED")
        with patch.object(rt, "MAX_LEGACY_BODY", 2):
            self.assert_error(raw("rse2-open"), "SIZE_LIMIT")

    def test_cli_real_process_with_spaces_and_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, output = Path(tmp) / "configuration with spaces.RT", Path(tmp) / "result.json"
            source.write_bytes(raw("rse5-c4-flags4"))
            proc = subprocess.run([sys.executable, str(ROOT / "decoders/Python/reese_tunnel.py"),
                                   str(source), "-o", str(output)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, "")
            self.assertEqual(proc.stderr, "")
            self.assertEqual(json.loads(output.read_text("utf-8")), EXPECTED)

    def test_cli_password_file_and_non_echo_prompt(self):
        name = "rse5-c4-flags2"
        with tempfile.TemporaryDirectory() as tmp:
            source, password = Path(tmp) / "config.RT", Path(tmp) / "password.txt"
            source.write_bytes(raw(name))
            password.write_text(CASES[name]["password"] + "\n", encoding="utf-8")
            for args in [[str(source), "--password-file", str(password)], [str(source), "--ask-password"]]:
                stdout = io.StringIO()
                with patch.object(rt.getpass, "getpass", return_value=CASES[name]["password"]), contextlib.redirect_stdout(stdout):
                    self.assertEqual(rt.main(args), 0)
                self.assertEqual(json.loads(stdout.getvalue()), EXPECTED)

    def test_cli_failure_does_not_create_output_or_leak_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, output = Path(tmp) / "config.RT", Path(tmp) / "result.json"
            source.write_bytes(raw("rse5-c4-flags7"))
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(rt.main([str(source), "-o", str(output)]), 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(json.loads(stderr.getvalue())["error"], "HWID_REQUIRED")
            self.assertNotIn(CASES["rse5-c4-flags7"]["password"], stderr.getvalue())
            self.assertFalse(output.exists())

    def test_cli_missing_file_and_usage_exit_2(self):
        with contextlib.redirect_stderr(io.StringIO()), tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(rt.main([str(Path(tmp) / "missing.RT")]), 2)
            with self.assertRaises(SystemExit) as ctx:
                rt.main([])
            self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
