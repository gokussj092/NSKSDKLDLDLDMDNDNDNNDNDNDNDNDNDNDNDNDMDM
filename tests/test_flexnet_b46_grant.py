"""Authorized-import capture tests; all credentials and profiles are synthetic."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from decoders.Python import flex, flexnet_b42 as codec
from scripts.apk_analysis.flexnet_collect_grant import collect, collect_offline_inner, PREFIX, OFFLINE_PREFIX

ROOT = Path(__file__).resolve().parents[1]
V = json.loads((ROOT / "tests/golden/flexnet_b46_vectors.json").read_text())
PROFILE = base64.b64decode(V["online"])
CAPTURE = (ROOT / "tests/golden/flexnet_b46_grant_capture.json").read_bytes()
OBJ = json.loads(CAPTURE)
GRANT = base64.b64decode(OBJ["grantBase64"])
CHALLENGE = base64.b64decode(OBJ["challengeBase64"])
V6 = base64.b64decode(V["v6"])
INNER = base64.b64decode(V["offline"])
OFFLINE_OBJ = {"schema": "flexnet-v6-opened-inner/1", "fileSha256": hashlib.sha256(V6).hexdigest(),
               "innerBase64": V["offline"]}


def capture_with(**changes):
    return json.dumps({**OBJ, **changes}).encode()


def offline_log(**changes):
    return ("[console] " + OFFLINE_PREFIX + json.dumps({**OFFLINE_OBJ, **changes}) + "\n").encode()


class FlexB46Grant(unittest.TestCase):
    def assert_code(self, code, function, *args, **kwargs):
        with self.assertRaises(codec.DecodeError) as error:
            function(*args, **kwargs)
        self.assertEqual(error.exception.code, code)

    def test_jdk_capture_opens_complete_xml_and_protected_properties(self):
        self.assertEqual(codec.file_key_from_grant(PROFILE, GRANT, CHALLENGE).hex(), V["fileKey"])
        self.assertEqual(codec.decrypt_profile_xml(PROFILE, grant_capture=CAPTURE), V["xml"])
        expected = codec.decode(PROFILE, file_key=bytes.fromhex(V["fileKey"]))
        self.assertEqual(codec.decode(PROFILE, grant_capture=CAPTURE), expected)
        self.assertEqual(flex.flex_decrypt_bytes(PROFILE, grant_capture=CAPTURE), V["xml"])
        normalized = json.loads(flex.run(PROFILE, grant_capture=CAPTURE))
        self.assertEqual(normalized["rawProperties"], expected["rawProperties"])
        self.assertEqual(normalized["tunnel"]["sni"], "real.example.invalid")

    def test_every_binding_byte_is_checked_and_wrong_content_key_fails_gcm(self):
        for offset in range(32, 117):
            with self.subTest(offset=offset):
                altered = bytearray(GRANT)
                altered[offset] ^= 1
                self.assert_code("GRANT_BINDING", codec.file_key_from_grant, PROFILE, bytes(altered), CHALLENGE)
        wrong_key = bytes([GRANT[0] ^ 1]) + GRANT[1:]
        capture = capture_with(grantBase64=base64.b64encode(wrong_key).decode())
        self.assert_code("AUTH_FAILED", codec.decode, PROFILE, grant_capture=capture)
        self.assertIsNone(flex.run(PROFILE, grant_capture=capture))
        self.assert_code("GRANT_BINDING", codec.file_key_from_grant, PROFILE, GRANT, b"x" * 32)
        self.assert_code("GRANT_BINDING", codec.decode, PROFILE, grant_capture=capture_with(fileSha256="0" * 64))

    def test_capture_schema_lengths_canonical_base64_duplicates_and_key_options(self):
        malformed = [capture_with(schema=1), capture_with(extra="ignored?"),
                     capture_with(fileSha256=OBJ["fileSha256"].upper()),
                     capture_with(grantBase64=base64.b64encode(b"x" * 256).decode()),
                     capture_with(challengeBase64="!" * 44),
                     capture_with(challengeBase64=OBJ["challengeBase64"][:-2] + "F="),
                     capture_with(grantBase64=None)]
        for capture in malformed:
            self.assert_code("GRANT_FORMAT", codec.decode, PROFILE, grant_capture=capture)
        duplicate = CAPTURE.rstrip()[:-1] + b',"schema":"flexnet-v5-authorized-grant/1"}'
        self.assert_code("INVALID_JSON", codec.decode, PROFILE, grant_capture=duplicate)
        self.assert_code("SIZE_LIMIT", codec.decode, PROFILE, grant_capture=b" " * 2049)
        self.assert_code("KEY_OPTIONS", codec.decode, PROFILE, grant_capture=CAPTURE, file_key=b"x" * 32)
        self.assert_code("GRANT_FORMAT", codec.file_key_from_grant, PROFILE, GRANT[:-1], CHALLENGE)
        self.assert_code("GRANT_FORMAT", codec.file_key_from_grant, PROFILE, GRANT, CHALLENGE[:-1])

    def test_grants_are_not_accepted_for_other_profile_modes_or_catalogs(self):
        for name in ("offline", "v6"):
            data = base64.b64decode(V[name])
            obj = {**OBJ, "fileSha256": hashlib.sha256(data).hexdigest()}
            self.assert_code("GRANT_FORMAT", codec.decode, data, grant_capture=json.dumps(obj).encode())
        self.assert_code("GRANT_FORMAT", codec.decode, b"{}", grant_capture=CAPTURE)
        old = json.loads((ROOT / "tests/golden/flexnet_b42_vectors.json").read_text())
        self.assertIsNone(flex.run(base64.b64decode(old["offline"]), grant_capture=CAPTURE))

    def test_both_cli_entrypoints_accept_capture_and_reject_conflicting_options(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            source, capture = folder / "profile.flex", folder / "capture.json"
            source.write_bytes(PROFILE)
            capture.write_bytes(CAPTURE)
            for name in ("flex.py", "flexnet_b42.py"):
                cmd = [sys.executable, str(ROOT / "decoders/Python" / name), str(source), "--grant-capture", str(capture)]
                opened = subprocess.run(cmd, cwd=tmp, capture_output=True, timeout=10)
                self.assertEqual(opened.returncode, 0, opened.stderr.decode())
                self.assertEqual(json.loads(opened.stdout)["protectedFields"]["customSni"], "real.example.invalid")
                failed = subprocess.run(cmd + ["--file-key-file", str(capture)], cwd=tmp, capture_output=True, timeout=10)
                self.assertEqual(failed.returncode, 2)
                self.assertEqual(failed.stdout, b"")

    def test_collector_verifies_full_decode_before_creating_private_non_overwritten_file(self):
        invalid = capture_with(grantBase64=base64.b64encode(b"x" * 117).decode())
        invalid_log = ("noise\n" + PREFIX + invalid.decode() + "\n" + PREFIX + "{}\n").encode()
        self.assert_code("CAPTURE_NOT_FOUND", collect, PROFILE, invalid_log)
        valid_log = invalid_log + ("[console] " + PREFIX + json.dumps(OBJ) + "\n").encode()
        self.assertEqual(json.loads(collect(PROFILE, valid_log)), OBJ)
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            profile, log, output = (folder / name for name in ("a.flex", "frida.log", "capture.json"))
            profile.write_bytes(PROFILE)
            log.write_bytes(valid_log)
            cmd = [sys.executable, str(ROOT / "scripts/apk_analysis/flexnet_collect_grant.py"), str(profile), str(log), str(output)]
            done = subprocess.run(cmd, cwd=tmp, capture_output=True, timeout=10)
            self.assertEqual(done.returncode, 0, done.stderr.decode())
            self.assertEqual(json.loads(output.read_bytes()), OBJ)
            if os.name == "posix":
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            retry = subprocess.run(cmd, cwd=tmp, capture_output=True, timeout=10)
            self.assertEqual(retry.returncode, 1)
            self.assertEqual(json.loads(output.read_bytes()), OBJ)
            self.assertNotIn(OBJ["grantBase64"].encode(), done.stdout + done.stderr + retry.stdout + retry.stderr)

    def test_v6_observed_inner_matches_jdk_and_opens_without_exporting_a_keystore_key(self):
        inner = collect_offline_inner(V6, offline_log())
        self.assertEqual(inner, INNER)
        self.assertEqual(codec.decrypt_profile_xml(inner), V["xml"])
        decoded_v6 = codec.decode(V6, offline_key=bytes.fromhex(V["offlineKey"]))
        self.assertEqual(codec.decode(inner), {**decoded_v6, "format": "FLXCFG-v5"})

    def test_v6_collector_rejects_other_file_and_modified_inner_gcm_tags(self):
        self.assert_code("CAPTURE_NOT_FOUND", collect_offline_inner, V6, offline_log(fileSha256="0" * 64))
        altered_outer = V6[:-1] + bytes([V6[-1] ^ 1])
        self.assert_code("CAPTURE_NOT_FOUND", collect_offline_inner, altered_outer, offline_log())
        for offset in (77, len(INNER) - 1):
            inner = bytearray(INNER)
            inner[offset] ^= 1
            log = offline_log(innerBase64=base64.b64encode(inner).decode())
            self.assert_code("CAPTURE_NOT_FOUND", collect_offline_inner, V6, log)
            self.assertEqual(collect_offline_inner(V6, log + offline_log()), INNER)

    def test_v6_collector_rejects_wrong_schema_duplicates_lengths_and_profile_modes(self):
        for changes in ({"schema": 1}, {"extra": "ignored?"}, {"innerBase64": V["offline"][:-4]},
                        {"innerBase64": "!" * len(V["offline"])}, {"innerBase64": V["online"]}):
            self.assert_code("CAPTURE_NOT_FOUND", collect_offline_inner, V6, offline_log(**changes))
        duplicate = (OFFLINE_PREFIX + json.dumps(OFFLINE_OBJ)[:-1] + ',"schema":"flexnet-v6-opened-inner/1"}\n').encode()
        self.assert_code("CAPTURE_NOT_FOUND", collect_offline_inner, V6, duplicate)
        self.assert_code("CAPTURE_FORMAT", collect_offline_inner, PROFILE, offline_log())
        self.assert_code("CAPTURE_FORMAT", collect_offline_inner, INNER, offline_log())
        self.assert_code("SIZE_LIMIT", collect_offline_inner, V6, b"x" * (8 * 1024 * 1024 + 1))

    def test_v6_collector_cli_creates_private_inner_and_does_not_treat_it_as_a_grant(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            profile, log, output = (folder / name for name in ("v6.flex", "frida.log", "inner.flex"))
            profile.write_bytes(V6)
            log.write_bytes(offline_log())
            cmd = [sys.executable, str(ROOT / "scripts/apk_analysis/flexnet_collect_grant.py"), str(profile), str(log), str(output)]
            rejected = subprocess.run(cmd, cwd=tmp, capture_output=True, timeout=10)
            self.assertEqual(rejected.returncode, 1)
            self.assertFalse(output.exists())
            opened = subprocess.run(cmd + ["--offline-inner"], cwd=tmp, capture_output=True, timeout=10)
            self.assertEqual(opened.returncode, 0, opened.stderr.decode())
            self.assertEqual(output.read_bytes(), INNER)
            if os.name == "posix":
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            repeat = subprocess.run(cmd + ["--offline-inner"], cwd=tmp, capture_output=True, timeout=10)
            self.assertEqual(repeat.returncode, 1)
            decoded = subprocess.run([sys.executable, str(ROOT / "decoders/Python/flex.py"), str(output)], cwd=tmp, capture_output=True, timeout=10)
            self.assertEqual(decoded.returncode, 0, decoded.stderr.decode())
            self.assertEqual(json.loads(decoded.stdout)["protectedFields"]["customSni"], "real.example.invalid")


if __name__ == "__main__":
    unittest.main()
