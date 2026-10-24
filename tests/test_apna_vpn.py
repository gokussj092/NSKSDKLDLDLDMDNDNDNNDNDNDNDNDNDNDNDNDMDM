"""APNA complete catalog/profile compatibility; all inputs are synthetic."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

DECODER = Path(__file__).resolve().parents[1] / "decoders/Python/apps/APNA_VPN/server_catalog_decoder.py"
spec = importlib.util.spec_from_file_location("apna_catalog", DECODER)
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


def seal(plaintext: bytes) -> bytes:
    """Independent encryption oracle based on Dalvik LBm.d, not the reader MX."""
    delta = 0x9e5729b1
    mask = (1 << 32) - 1
    n = (len(plaintext) + 3) // 4
    pad = plaintext.ljust(n * 4, b"\x00")
    words = list(struct.unpack("<" + "I" * n, pad)) + [len(plaintext)]
    count = len(words)
    key = struct.unpack("<4I", b"...|...".ljust(16, b"\0"))
    z = words[-1]
    total = 0
    for _ in range(6 + 52 // count):
        total = (total + delta) & mask
        e = (total >> 2) & 3
        for i in range(count - 1):
            y = words[i + 1]
            mx = (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^
                  ((total ^ y) + (key[(i & 3) ^ e] ^ z))) & mask
            words[i] = (words[i] + mx) & mask
            z = words[i]
        y = words[0]
        mx = (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^
              ((total ^ y) + (key[((count - 1) & 3) ^ e] ^ z))) & mask
        words[-1] = (words[-1] + mx) & mask
        z = words[-1]
    return base64.b64encode(struct.pack("<" + "I" * count, *words))


def profile_seal(text: str) -> bytes:
    """Independent exporter: Java UTF-16 code units encoded with JNI UTF-8."""
    units = struct.unpack(">" + "H" * (len(text.encode("utf-16-be")) // 2), text.encode("utf-16-be"))
    raw = b"".join(chr(unit).encode("utf-8", "surrogatepass") for unit in units)
    raw = raw.replace(b"\0", b"\xc0\x80")
    key = bytes.fromhex("342550645863683e666b505d")
    return bytes(value ^ key[index % 12] for index, value in enumerate(raw)).hex().encode("ascii")


class APNATests(unittest.TestCase):
    def setUp(self):
        self.catalog = {
            "Free_servers": [{"server_name": "Fixture 🛠", "server_host": "example.invalid",
                              "server_port": "443", "password": "synthetic-only"}],
            "Premium_servers": [], "Vip_servers": [], "Private_servers": [],
            "Payloads": [{"friendly_name": "test", "payload": "GET / HTTP/1.1\r\n"}],
            "Version": "3.9", "OtherField": {"nested": [True, None, "é"]},
        }
        self.plain = json.dumps(self.catalog, ensure_ascii=False, separators=(",", ":")).encode()
        self.encrypted = seal(self.plain)

    def test_exact_plaintext_and_nested_fields(self):
        self.assertEqual(reader.decode_json_bytes(self.encrypted), self.plain)
        self.assertEqual(json.loads(reader.run(self.encrypted)), self.catalog)
        info = reader.summary(self.plain)
        self.assertEqual(info["serverCounts"]["Free_servers"], 1)
        self.assertEqual(info["payloadCount"], 1)
        self.assertNotIn("synthetic-only", json.dumps(info))

    def test_malformed_or_tampered_data_rejected(self):
        with self.assertRaises(reader.CatalogError):
            reader.run(b"not base64%%")
        with self.assertRaises(reader.CatalogError):
            reader.run(base64.b64encode(b"1234"))
        changed = bytearray(base64.b64decode(self.encrypted))
        changed[4] ^= 128
        with self.assertRaises(reader.CatalogError):
            reader.run(base64.b64encode(changed))
        with self.assertRaises(reader.CatalogError):
            reader.run(seal(b'{"not_a_catalog":true}'))

    def test_cli_summary_excludes_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "synthetic.json"
            path.write_bytes(self.encrypted)
            call = [sys.executable, str(DECODER), "--input", str(path), "--summary"]
            done = subprocess.run(call, capture_output=True, check=True, timeout=15)
            self.assertEqual(json.loads(done.stdout)["payloadCount"], 1)
            self.assertNotIn(b"synthetic-only", done.stdout)

    def test_catalog_rejects_ambiguous_json_and_unexpected_records(self):
        malformed = [
            b'{"Version":"1","Version":"2","Free_servers":[],"Payloads":[]}',
            b'{"Version":"1","Free_servers":[],"Payloads":[],"n":NaN}',
            b'{"Version":"1","Free_servers":[],"Payloads":[],"n":1e9999}',
            b'{"Version":"1","Free_servers":[1],"Payloads":[]}',
            b'{"Version":1,"Free_servers":[],"Payloads":[]}',
            b'{"Version":"1","Free_servers":[],"Payloads":[],"n":"\\ud800"}',
            b'{"Version":"1","Free_servers":[],"Payloads":[],"n":' + b'['*66 + b'0' + b']'*66 + b'}',
        ]
        for raw in malformed:
            with self.subTest(raw=raw[:100]), self.assertRaises(reader.CatalogError):
                reader.decode_json_bytes(seal(raw))

    def profiles(self):
        for password in ("", "synthetic-lock"):
            obj = {"friendly_name": "Prueba 🛠 é", "tweak_password": password,
                   "payload": "GET / HTTP/1.1\r\nHost: example.invalid\r\n",
                   "tweak_expiry": "2030-01-01", "hwid_lock": "synthetic-hwid",
                   "block_rooted": True, "unknown": {"all": [False, None, 12]}}
            plain = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
            yield obj, plain.encode(), profile_seal(plain)

    def test_locked_and_unlocked_profiles_preserve_every_field_and_unicode(self):
        for obj, plain, encrypted in self.profiles():
            self.assertEqual(reader.decode_profile_bytes(encrypted), plain)
            self.assertEqual(reader.decode_profile_bytes(b"apnavpn://" + encrypted), plain)
            self.assertEqual(json.loads(reader.decode_profile_bytes(encrypted.upper())), obj)

    def test_invalid_profiles_fail_without_returning_ciphertext(self):
        for raw in (b"", b"apnavpn://", b"a", b"ag", b"00", b"apnavpn://00 ",
                    profile_seal('{"friendly_name":"x"}'),
                    profile_seal('{"friendly_name":"x","tweak_password":1}'),
                    profile_seal('{"friendly_name":"x","tweak_password":"","friendly_name":"y"}'),
                    profile_seal('{"friendly_name":"x","tweak_password":"","n":NaN}')):
            with self.subTest(raw=raw[:100]), self.assertRaises(reader.CatalogError):
                reader.decode_profile_bytes(raw)

    def test_worker_complete_catalog_file_and_text(self):
        sys.path.insert(0, str(DECODER.parents[4] / "cloud/workers/python"))
        from engine import decode_provider_catalog, decode_file, decode_text
        out = decode_provider_catalog("apna-vpn", self.encrypted)
        self.assertEqual(out["structuredJson"], self.catalog)
        self.assertFalse(out["isPartial"])
        for obj, _, encrypted in self.profiles():
            for out in (decode_file("apnavpn", encrypted), decode_text("apnavpn://" + encrypted.decode())):
                self.assertEqual(out["structuredJson"], obj)
                self.assertEqual(json.loads(out["rawText"]), obj)
                self.assertFalse(out["isPartial"])

    @unittest.skipUnless(shutil.which("java"), "JDK required for independent whole-plaintext comparison")
    def test_independent_jdk_full_catalog_and_jni_profiles(self):
        oracle = DECODER.parents[4] / "tests/golden/apna_oracle.java"
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "synthetic.enc"
            cases = [("catalog", self.encrypted, self.plain)]
            cases.extend(("profile", encrypted, plain) for _, plain, encrypted in self.profiles())
            for mode, encrypted, plain in cases:
                path.write_bytes(encrypted)
                done = subprocess.run(["java", str(oracle), mode, str(path)], check=True,
                                      capture_output=True, timeout=30)
                self.assertEqual(done.stdout, plain)

    def test_cli_private_output_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "synthetic.enc"
            target = Path(temp) / "plain.json"
            source.write_bytes(self.encrypted)
            command = [sys.executable, str(DECODER), "--input", str(source), "--output", str(target)]
            subprocess.run(command, check=True, capture_output=True, timeout=15)
            self.assertEqual(target.read_bytes(), self.plain)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            again = subprocess.run(command, capture_output=True, timeout=15)
            self.assertEqual(again.returncode, 1)
            self.assertEqual(target.read_bytes(), self.plain)

    def test_cli_file_and_link(self):
        _, plain, encrypted = next(self.profiles())
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "test.apnavpn"; source.write_bytes(encrypted)
            for options in (["--file", str(source)], ["--text", "apnavpn://" + encrypted.decode()]):
                done = subprocess.run([sys.executable, str(DECODER), *options], check=True,
                                      capture_output=True, timeout=15)
                self.assertEqual(done.stdout, plain)

    def test_download_uses_fixed_source_headers_and_limits(self):
        response = MagicMock(status=200, headers={})
        response.read.return_value = self.encrypted
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with patch.object(reader, "build_opener", return_value=opener):
            self.assertEqual(reader.download(), self.encrypted)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://paperonboard.com/updater/3c3c4c58d864ca394da16656b4d0c4")
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.get_header("User-agent"), "Dalvik/2.1.0")
        self.assertEqual(request.get_header("Accept-encoding"), "identity")
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 25)
        response.read.assert_called_once_with(reader.MAX_INPUT + 1)
        for status, headers, body in [(403, {}, b"x"), (200, {"Content-Encoding": "gzip"}, b"x"),
                                     (200, {}, b""), (200, {}, b"x" * (reader.MAX_INPUT + 1))]:
            response.status, response.headers, response.read.return_value = status, headers, body
            with patch.object(reader, "build_opener", return_value=opener), self.assertRaises(reader.CatalogError):
                reader.download()
        with self.assertRaises(reader.CatalogError):
            reader._NoRedirect().redirect_request(None, None, 302, "", {}, reader.CATALOG_URL)

    def test_default_cli_download_and_empty_text_stays_offline(self):
        previous = os.getcwd()
        with tempfile.TemporaryDirectory() as temp:
            try:
                os.chdir(temp)
                with patch.object(sys, "argv", ["apna_vpn.py"]), patch.object(reader, "download", return_value=self.encrypted):
                    self.assertEqual(reader.main(), 0)
                self.assertEqual(Path("apna_vpn_catalogo.json").read_bytes(), self.plain)
                with patch.object(sys, "argv", ["apna_vpn.py", "--text", ""]), patch.object(reader, "download") as download:
                    self.assertEqual(reader.main(), 1)
                    download.assert_not_called()
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()
