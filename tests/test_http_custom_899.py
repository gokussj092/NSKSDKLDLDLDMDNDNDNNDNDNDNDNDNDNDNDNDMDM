"""HCX4 real-format regressions and independent native-KDF synthetic vectors."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloud.workers.python.engine import DecodeFailure, decode_file
from decoders.Python.HTTPCUSTOM import run as bot_run
from decoders.Python.apps.HTTP_Custom import codec
from decoders.Python.apps.HTTP_Custom.crypto import native_fold, sha256_from_state
from decoders.Python.apps.HTTP_Custom.file_decoder import run
from tests.golden.http_custom_899 import HWID, PASSWORD, MAIN, PROFILE, make_file, seal

ROOT = Path(__file__).resolve().parents[1]


class HttpCustom899Tests(unittest.TestCase):
    def test_sha256_compression_padding_boundaries(self):
        initial = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)
        for length in (0, 1, 55, 56, 63, 64, 65, 119, 120, 1024):
            data = bytes(index % 256 for index in range(length))
            self.assertEqual(sha256_from_state(initial, data, 0), hashlib.sha256(data).digest())

    def test_native_fold_known_answer(self):
        self.assertEqual(native_fold(b"hc-envelope-seal-v4 xyz.easypro.httpcustom").hex(),
                         "3bca1c3209a7dc686bd04939cbeb8ff88b34f4703cb7dbdfec1512dc1ea6ca38")
        self.assertEqual(codec.OUTER_KEY.hex(),
                         "aa69ca025625f2bd9c675f5d7091dda06ad98cb38ba4476683eb0d8d8025af49")

    def test_all_four_native_key_vectors_and_complete_typed_output(self):
        for locked in (False, True):
            for protected in (False, True):
                with self.subTest(locked=locked, protected=protected):
                    clear = codec.decrypt(make_file(locked=locked, protected=protected),
                                          PASSWORD if protected else None, HWID.lower() if locked else None)
                    expected = dict(PROFILE, custom_payload_sidecar_hex="ff00fe")
                    self.assertEqual(clear["config"], [expected])
                    self.assertEqual(clear["main"], MAIN)
                    self.assertEqual(clear["other_sections"], [{"label": "extra", "content": {"preserved": [None, False, 0]}}])
                    self.assertEqual(clear["envelope"]["z"], {"preserve": [1, None, False, {}]})
                    self.assertEqual(clear["protections"]["blockRoot"], False)
                    self.assertEqual(clear["config"][0]["port"], 443)
                    self.assertEqual(clear["config"][0]["options"]["port"], 8080)

    def test_raw_and_repeated_utf8_latin1_carriers_preserve_crlf(self):
        expected = codec.decrypt(make_file())
        for depth in (1, 2):
            self.assertEqual(codec.decrypt(make_file(carrier=depth)), expected)
        self.assertEqual(codec.decrypt(make_file(sidecar=b"true"))["config"][0]["custom_payload_sidecar"], "true")

    def test_credential_requirements_and_wrong_values(self):
        for flags, expected in [({"protected": True}, "PASSWORD_REQUIRED"),
                                ({"locked": True}, "HWID_REQUIRED"),
                                ({"locked": True, "protected": True}, "HWID_PASSWORD_REQUIRED")]:
            with self.subTest(flags=flags), self.assertRaisesRegex(codec.HCError, "^" + expected + "$"):
                codec.decrypt(make_file(**flags))
        for password, hwid in [("wrong", HWID), (PASSWORD, "B" * 32)]:
            with self.subTest(password_correct=password == PASSWORD), self.assertRaisesRegex(codec.HCError, "^AUTH_FAILED$"):
                codec.decrypt(make_file(locked=True, protected=True), password, hwid)

    def test_each_authenticated_layer_rejects_tampering(self):
        for layer in ("outer", "main", "profile", "hpr", "sidecar", "slot"):
            with self.subTest(layer=layer), self.assertRaises(codec.HCError):
                codec.decrypt(make_file(locked=True, protected=True, tamper=layer), PASSWORD, HWID)
        # The historical fallback must not accidentally accept a damaged HCX4.
        self.assertIsNone(bot_run(make_file(tamper="outer")))

    def test_unsupported_formats_and_argon_resource_bounds(self):
        original = codec.open_envelope(make_file(protected=True))
        for key, value, code in [("b", 11, "UNSUPPORTED_SCHEMA"), ("e", "n13", "UNSUPPORTED_SCHEDULE"),
                                  ("l", 999, "ARGON2_LIMIT"), ("m", 2**40, "ARGON2_LIMIT")]:
            envelope = copy.deepcopy(original)
            envelope[key] = value
            with self.subTest(field=key), self.assertRaisesRegex(codec.HCError, code):
                codec.decrypt(seal(envelope), PASSWORD)
        for bad in (b"", b"not a profile", make_file()[:39]):
            with self.assertRaises(codec.UnrecognizedFormat):
                codec.decrypt(bad)
        with self.assertRaisesRegex(codec.HCError, "INVALID_CREDENTIAL"):
            run(b"legacy-or-unrecognized", password={"invalid": True})
        with self.assertRaisesRegex(codec.HCError, "INVALID_FILE_SIZE"):
            codec.open_envelope(b"x" * (codec.MAX_FILE_BYTES + 1))

    def test_cli_and_bot_entrypoint(self):
        data = make_file()
        self.assertEqual(json.loads(run(data)), json.loads(bot_run(data)))
        with tempfile.TemporaryDirectory() as folder:
            profile = Path(folder) / "profile.HC"
            profile.write_bytes(data)
            canonical = subprocess.run([sys.executable, str(ROOT / "decoders/Python/HTTPCUSTOM.py"), str(profile)],
                                       capture_output=True, text=True, cwd=folder, timeout=15)
            self.assertEqual(canonical.returncode, 0, canonical.stderr)
            self.assertEqual(json.loads(canonical.stdout)["main"], MAIN)
            profile.write_bytes(make_file(locked=True, protected=True, carrier=1))
            for script in ("file_decoder.py", "HTTP_Custom.py"):
                proc = subprocess.run([sys.executable, str(ROOT / "decoders/Python/apps/HTTP_Custom" / script),
                                       str(profile), "--auth-stdin"], input=json.dumps({"password": PASSWORD, "hwid": HWID}),
                                      text=True, capture_output=True, cwd=folder, timeout=15)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(json.loads(proc.stdout)["main"], MAIN)
                self.assertEqual(proc.stderr, "")

    def test_cloud_worker_all_lock_modes_and_safe_errors(self):
        for locked, protected in ((False, False), (False, True), (True, False), (True, True)):
            credentials = {}
            if locked:
                credentials["hwid"] = HWID
            if protected:
                credentials["password"] = PASSWORD
            response = decode_file("hc", make_file(locked=locked, protected=protected), credentials=credentials or None)
            self.assertEqual(response["structuredJson"]["main"], MAIN)
            self.assertEqual(response["structuredJson"]["config"][0]["flags"], 0xffffffff)
            self.assertFalse(response["isPartial"])
        for credentials, code in [(None, "HWID_PASSWORD_REQUIRED"),
                                  ({"password": "wrong", "hwid": HWID}, "AUTH_FAILED")]:
            with self.assertRaises(DecodeFailure) as caught:
                decode_file("hc", make_file(locked=True, protected=True), credentials=credentials)
            self.assertEqual(caught.exception.code, code)


if __name__ == "__main__":
    unittest.main()
