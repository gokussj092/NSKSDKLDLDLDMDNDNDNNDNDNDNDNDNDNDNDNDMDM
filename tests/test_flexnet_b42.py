"""FlexNet B42 vectors independently produced with OpenJDK/JCE.

All keys and server records in this suite are synthetic; no live requests.
"""
import base64
import contextlib
import gzip
import io
import json
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA1, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature.pss import MGF1
from decoders.Python import flex, flexnet_b42 as b42
from decoders.Python.text_structured_protocols import decode_flex

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = json.loads((ROOT / "tests/golden/flexnet_b42_vectors.json").read_text("utf-8"))
OFFLINE = base64.b64decode(GOLDEN["offline"])
ONLINE = base64.b64decode(GOLDEN["online"])
CATALOG = base64.b64decode(GOLDEN["catalog"])
FILE_KEY = bytes.fromhex(GOLDEN["fileKey"])


def online_content(compressed):
    header = ONLINE[:41] + struct.pack(">I", len(compressed) + 16)
    cipher = AES.new(FILE_KEY, AES.MODE_GCM, nonce=header[29:41])
    cipher.update(header)
    body, tag = cipher.encrypt_and_digest(compressed)
    return header + body + tag


class FlexB42Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa = RSA.generate(2048)

    def assert_error(self, data, code, **kwargs):
        with self.assertRaises(b42.DecodeError) as ctx:
            b42.decode(data, **kwargs)
        self.assertEqual(ctx.exception.code, code)
        self.assertIsNone(b42.run(data, **kwargs))

    def envelope(self, *, wrong_mgf=False, document=None):
        key, nonce, aad = bytes(range(32)), bytes(range(12)), "synthetic-request-aad"
        document = GOLDEN["catalogExpected"] if document is None else document
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(aad.encode())
        body, tag = cipher.encrypt_and_digest(json.dumps(document).encode())
        rsa = PKCS1_OAEP.new(self.rsa.public_key(), hashAlgo=SHA256,
                             mgfunc=lambda seed, n: MGF1(seed, n, SHA256 if wrong_mgf else SHA1))
        return json.dumps({"ok": True, "mode": "flexnet-servers-v1",
                           "encryptedKey": base64.b64encode(rsa.encrypt(key)).decode(),
                           "nonce": base64.b64encode(nonce).decode(),
                           "ciphertext": base64.b64encode(body + tag).decode(), "aad": aad}).encode()

    def test_independent_java_offline_xml_and_complete_properties(self):
        self.assertEqual(b42.decrypt_profile_xml(OFFLINE), GOLDEN["xml"])
        result = b42.decode(OFFLINE)
        self.assertEqual(len(result["rawProperties"]), 8)
        self.assertEqual(result["rawProperties"]["custom.unknown"], "keep-me")
        self.assertEqual(result["rawProperties"]["proxyPayload"], "GET / HTTP/1.1\r\nHost: example.invalid")
        self.assertEqual(result["xmlComments"], ["Synthetic FlexNet 日本語"])
        self.assertTrue(result["embeddedJson"]["remoteServerSnapshot"]["futureField"]["keep"])
        self.assertEqual(json.loads(b42.run(OFFLINE)), result)

    def test_independent_java_online_needs_authorized_key(self):
        self.assert_error(ONLINE, "ONLINE_AUTH_REQUIRED")
        self.assertEqual(b42.decrypt_profile_xml(ONLINE, file_key=FILE_KEY), GOLDEN["xml"])
        self.assertEqual(b42.decode(ONLINE, file_key=FILE_KEY), b42.decode(OFFLINE))
        self.assert_error(ONLINE, "AUTH_FAILED", file_key=b"x" * 32)
        self.assert_error(ONLINE, "KEY_FORMAT", file_key=b"short")

    def test_builtin_java_catalog_preserves_all_seven_unknown_records(self):
        result = b42.decode(CATALOG)
        self.assertEqual(result, GOLDEN["catalogExpected"])
        self.assertEqual(len(result["servers"]), 7)
        self.assertTrue(result["servers"][0]["unknown"]["preserve"])

    def test_existing_bot_and_text_routes_use_v5_without_registry_changes(self):
        self.assertEqual(flex.flex_decrypt_bytes(OFFLINE), GOLDEN["xml"])
        self.assertEqual(json.loads(flex.run(OFFLINE))["rawProperties"]["custom.unknown"], "keep-me")
        for scheme in ["flex://", "flexnet://"]:
            self.assertIsNotNone(decode_flex(scheme + GOLDEN["offline"]))
            self.assertIsNone(decode_flex(scheme + GOLDEN["online"]))
        self.assertIsNone(flex.run(ONLINE))

    def test_header_inspection_does_not_claim_plaintext_or_authentication(self):
        info = b42.inspect_profile(ONLINE)
        self.assertEqual(info["mode"], "online")
        self.assertTrue(info["requiresAuthorizedFileKey"])
        self.assertEqual(info["minimumClientBuild"], 42)
        self.assertEqual(info["headerBytes"], 45)
        self.assertNotIn("rawProperties", info)
        self.assertNotIn("authenticated", info)

    def test_all_offline_crypto_layers_authenticate_header_and_data(self):
        for offset in [17, 32, 33, 64, 65, 76, 77, 124, 125, 136, 141, len(OFFLINE)-1]:
            with self.subTest(offset=offset):
                data = bytearray(OFFLINE)
                data[offset] ^= 1
                self.assert_error(bytes(data), "AUTH_FAILED")

    def test_online_and_builtin_tag_failures_have_no_partial_output(self):
        for data, options in [(ONLINE, {"file_key": FILE_KEY}), (CATALOG, {})]:
            corrupt = bytearray(data)
            corrupt[-1] ^= 1
            self.assert_error(bytes(corrupt), "AUTH_FAILED", **options)

    def test_versions_modes_generation_minimum_and_lengths(self):
        for offset, value, code in [(6, 7, "UNSUPPORTED_VERSION"), (7, 3, "UNSUPPORTED_MODE"),
                                    (8, 2, "UNSUPPORTED_SUITE"), (16, 2, "UNSUPPORTED_GENERATION")]:
            corrupt = bytearray(OFFLINE)
            corrupt[offset] = value
            self.assert_error(bytes(corrupt), code)
        corrupt = bytearray(ONLINE)
        struct.pack_into(">I", corrupt, 9, b42.CLIENT_BUILD + 1)
        self.assert_error(bytes(corrupt), "MINIMUM_BUILD")
        self.assert_error(ONLINE[:-1], "TRUNCATED")
        self.assert_error(OFFLINE[:30], "TRUNCATED")
        for size in [6, 7, 8, 12, 44, 60]:
            self.assert_error(ONLINE[:size], "TRUNCATED")

    def test_authenticated_invalid_gzip_and_xml(self):
        for data in [b"not gzip", gzip.compress(b"<properties/>")[:-2], gzip.compress(b"<properties/>") + b"tail"]:
            self.assert_error(online_content(data), "INVALID_GZIP", file_key=FILE_KEY)
        for xml in [b"\xff", b"bad XML", b"<wrong/>",
                    b'<properties><entry key="x">a</entry><entry key="x">b</entry></properties>',
                    b'<!DOCTYPE properties [<!ENTITY x "bad">]><properties/>',
                    b'<properties><entry key="x"><nested/></entry></properties>']:
            self.assert_error(online_content(gzip.compress(xml)), "INVALID_XML", file_key=FILE_KEY)

    def test_input_and_decompression_limits(self):
        with patch.object(b42, "MAX_INPUT", 10):
            self.assert_error(OFFLINE, "SIZE_LIMIT")
        with patch.object(b42, "MAX_XML", 20):
            self.assert_error(OFFLINE, "SIZE_LIMIT")
        for data in [None, b"", 1, b"not JSON or FLXCFG"]:
            self.assertIsNone(b42.run(data))

    def test_remote_catalog_requires_recipient_private_key_and_exact_oaep(self):
        envelope = self.envelope()
        self.assert_error(envelope, "PRIVATE_KEY_REQUIRED")
        pem = self.rsa.export_key()
        self.assertEqual(b42.decode(envelope, private_key=pem), GOLDEN["catalogExpected"])
        self.assert_error(self.envelope(wrong_mgf=True), "AUTH_FAILED", private_key=pem)
        self.assert_error(envelope, "KEY_FORMAT", private_key=self.rsa.public_key().export_key())
        self.assert_error(self.envelope(document={"wrong": []}), "WRONG_DOCUMENT", private_key=pem)

    def test_remote_catalog_malformed_fields_and_authenticated_aad(self):
        pem = self.rsa.export_key()
        original = json.loads(self.envelope())
        for field, value, code in [("nonce", "!", "FORMAT_ERROR"), ("aad", 1, "FORMAT_ERROR"),
                                   ("aad", "changed", "AUTH_FAILED"), ("mode", "wrong", "FORMAT_ERROR")]:
            document = {**original, field: value}
            self.assert_error(json.dumps(document).encode(), code, private_key=pem)
        self.assert_error(b'{"ok":true,"ok":false}', "INVALID_JSON")

    def test_builtin_catalog_from_local_apk_and_size_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "synthetic.apk"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("assets/builtin_servers.dat", CATALOG)
            self.assertEqual(b42.decode(b42.builtin_from_apk(path)), GOLDEN["catalogExpected"])
            with patch.object(b42, "MAX_CATALOG", 10):
                with self.assertRaises(b42.DecodeError) as ctx:
                    b42.builtin_from_apk(path)
                self.assertEqual(ctx.exception.code, "SIZE_LIMIT")
            path.write_bytes(b"not zip")
            with self.assertRaises(b42.DecodeError):
                b42.builtin_from_apk(path)

    def test_cli_both_scripts_accept_offline_v5_and_preserve_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, output = Path(tmp) / "file with spaces.flex", Path(tmp) / "result.json"
            source.write_bytes(OFFLINE)
            for script, args in [("flex.py", []), ("flexnet_b42.py", ["-o", str(output)])]:
                proc = subprocess.run([sys.executable, str(ROOT / "decoders/Python" / script), str(source), *args],
                                       capture_output=True, text=True)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(proc.stderr, "")
                result = json.loads(output.read_text() if args else proc.stdout)
                self.assertEqual(result["rawProperties"]["sshServer"], "vpn.example.invalid")

    def test_cli_online_inspect_and_key_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, key = Path(tmp) / "online.flex", Path(tmp) / "key.bin"
            source.write_bytes(ONLINE)
            for data in [FILE_KEY, FILE_KEY.hex().encode() + b"\n"]:
                key.write_bytes(data)
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    self.assertEqual(b42.main([str(source), "--file-key-file", str(key)]), 0)
                self.assertEqual(json.loads(stdout.getvalue())["format"], "FLXCFG-v5")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(b42.main([str(source), "--inspect"]), 0)
            self.assertTrue(json.loads(stdout.getvalue())["requiresAuthorizedFileKey"])

    def test_cli_online_failure_does_not_create_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, output = Path(tmp) / "online.flex", Path(tmp) / "result.json"
            source.write_bytes(ONLINE)
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(b42.main([str(source), "-o", str(output)]), 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(json.loads(stderr.getvalue())["error"], "ONLINE_AUTH_REQUIRED")
            self.assertFalse(output.exists())

    def test_cli_missing_file_and_usage(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(b42.main([str(Path(tmp) / "missing.flex")]), 2)
            with self.assertRaises(SystemExit) as ctx:
                b42.main([])
            self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
