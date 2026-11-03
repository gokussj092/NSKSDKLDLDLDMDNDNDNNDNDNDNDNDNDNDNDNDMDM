"""Bot-only Ultra/Sandok family: 42 variants, native KDF/AEAD, legacy .ost."""
from __future__ import annotations
import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from Crypto.Cipher import AES, DES
from argon2.low_level import Type, hash_secret_raw

from decoders.Python import ultra
from spdecode.registry import DECODER_REGISTRY, get_supported_extension, validate_decoder_files

ROOT = Path(__file__).resolve().parents[1]


def seal(clear: bytes, password: bytes, mem: int, *, aad: bool, nonce: bytes) -> bytes:
    salt = bytes(range(16))
    key = hash_secret_raw(password, salt, time_cost=3, memory_cost=mem,
                          parallelism=1, hash_len=32, type=Type.ID)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(salt)
    ciphertext, tag = cipher.encrypt_and_digest(clear)
    return salt + nonce + ciphertext + tag


def config_fixture(profile: str, *, aad: bool = True, inner: bool = False) -> bytes:
    spec = ultra.ULTRA_CONFIGS[profile]
    config = {"Server": "example.invalid", "Enabled": False, "Port": 443,
              "Notes": "Prueba 日本語", "List": ["first", "second"]}
    if inner:
        encoded = seal(b"GET / HTTP/1.1", spec["password2"], spec["mem"],
                       aad=False, nonce=bytes(range(12, 24)))
        config["Payload"] = base64.b64encode(encoded).decode("ascii")
    plaintext = json.dumps(config, ensure_ascii=False).encode("utf-8")
    return base64.b64encode(seal(plaintext, spec["password"], spec["mem"],
                                 aad=aad, nonce=bytes(range(12))))


class UltraSandokBotTests(unittest.TestCase):
    def test_exact_42_extensions_and_41_new_bot_mappings(self):
        assert len(ultra.ULTRA_EXTS) == 42
        self.assertEqual(set(ultra.ULTRA_NAMES), ultra.ULTRA_EXTS)
        self.assertEqual(set(ultra.EXT_TO_KEY), ultra.ULTRA_EXTS)
        self.assertEqual(len(set(DECODER_REGISTRY) - {'solid','1ftnl','awg','creeb','kyz','stp','hexcm'}), 239)
        for suffix in ultra.ULTRA_EXTS:
            ext = suffix[1:]
            self.assertEqual(get_supported_extension("file" + suffix.upper()), ext)
            if ext == "ost":
                self.assertEqual(DECODER_REGISTRY[ext].script, "decoders/Python/ost.py")
            else:
                self.assertEqual(DECODER_REGISTRY[ext].script, "decoders/Python/ultra.py")
                self.assertEqual(DECODER_REGISTRY[ext].runtime, "python")
        self.assertEqual(validate_decoder_files(), [])

    def test_all_42_suffixes_decrypt_their_assigned_profile(self):
        """A positive synthetic fixture for every registered Ultra/Sandok extension."""
        samples = {}
        for suffix in sorted(ultra.ULTRA_EXTS):
            profile = ultra.EXT_TO_KEY[suffix]
            if profile not in samples:
                samples[profile] = config_fixture(profile, aad=True)
            with self.subTest(suffix=suffix, profile=profile):
                decoded = ultra.run(samples[profile], suffix)
                self.assertIsNotNone(decoded, suffix)
                obj = json.loads(decoded)
                self.assertEqual(obj["extension"], suffix)
                self.assertEqual(obj["config"]["_vpn_key"], profile)
                self.assertEqual(obj["config"]["Server"], "example.invalid")

    def test_ultra_authenticated_outer_and_inner_fields(self):
        data = config_fixture("ultratunnel", aad=True, inner=True)
        response = ultra.run(b"ultra://" + data, ".ultra")
        self.assertIsNotNone(response)
        actual = json.loads(response)
        self.assertEqual(actual["config"]["Payload"], "GET / HTTP/1.1")
        self.assertEqual(actual["config"]["Server"], "example.invalid")
        self.assertFalse(actual["config"]["Enabled"])
        self.assertEqual(actual["config"]["List"], ["first", "second"])
        self.assertEqual(actual["config"]["_vpn_key"], "ultratunnel")

    def test_modern_authenticated_inner_fields_use_aad_salt(self):
        profile = ultra.ULTRA_CONFIGS["ultratunnel"]
        for aad in (True, False):
            with self.subTest(aad=aad):
                ciphertext = seal(b"GET / HTTP/1.1\\r\\nHost: example.invalid",
                                  profile["password2"], profile["mem"],
                                  aad=aad, nonce=bytes(range(12, 24)))
                encoded = base64.b64encode(ciphertext).decode("ascii")
                self.assertEqual(ultra.decrypt_ultra_field(
                    encoded, profile["password2"], profile["mem"]),
                    "GET / HTTP/1.1\\r\\nHost: example.invalid")

                tampered = bytearray(ciphertext)
                tampered[-1] ^= 1
                invalid = base64.b64encode(tampered).decode("ascii")
                self.assertEqual(ultra.decrypt_ultra_field(
                    invalid, profile["password2"], profile["mem"]), invalid)

        self.assertEqual(ultra.decrypt_ultra_field(
            "NotEncrypted", profile["password2"], profile["mem"]), "NotEncrypted")

    def test_different_key_and_memory_profiles_without_aad(self):
        for suffix, profile in ((".tx", "txtunnel"),
                                (".flynet", "flynetvpn"),
                                (".mmt", "mmtunnel")):
            with self.subTest(suffix=suffix):
                raw = config_fixture(profile, aad=False)
                result = ultra.run(raw, suffix)
                self.assertIsNotNone(result)
                parsed = json.loads(result)["config"]
                self.assertEqual(parsed["_vpn_key"], profile)
                self.assertEqual(parsed["Notes"], "Prueba 日本語")

    def test_inner_field_rejects_invalid_authentication_tag(self):
        profile = ultra.ULTRA_CONFIGS["nurtunnel"]
        raw = bytearray(seal(b"protected", profile["password2"],
                             profile["mem"], aad=False, nonce=bytes(range(12))))
        encoded = base64.b64encode(raw).decode("ascii")
        self.assertEqual(ultra.decrypt_ultra_field(encoded,
            profile["password2"], profile["mem"]), "protected")
        raw[-1] ^= 1
        tampered = base64.b64encode(raw).decode("ascii")
        self.assertEqual(ultra.decrypt_ultra_field(tampered,
            profile["password2"], profile["mem"]), tampered)

    def test_ost_collision_uses_both_engines(self):
        ost = ROOT / "decoders/Python/ost.py"
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "synthetic.ost"
            target.write_bytes(config_fixture("default", aad=True))
            run = subprocess.run([sys.executable, str(ost), str(target)],
                cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout)["config"]["Server"], "example.invalid")

            legacy_key = base64.b64decode("4pyF2Y5PU1Q=")
            plaintext = b'<entry key="host">legacy.invalid</entry>\n'
            plaintext += b" " * (-len(plaintext) % 8)
            target.write_bytes(DES.new(legacy_key, DES.MODE_ECB).encrypt(plaintext))
            old = subprocess.run([sys.executable, str(ost), str(target)],
                cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertEqual(old.returncode, 0, old.stderr)
            self.assertIn("legacy.invalid", old.stdout)

    def test_rejects_unknown_suffix_and_malformed_inputs(self):
        self.assertIsNone(ultra.run(b"", ".ultra"))
        self.assertIsNone(ultra.run(b"broken", ".ultra"))
        self.assertIsNone(ultra.run(b"U29tZSB0ZXh0", ".ultra"))
        self.assertIsNone(ultra.run(b"not ultra", ".other"))


if __name__ == "__main__":
    unittest.main()
