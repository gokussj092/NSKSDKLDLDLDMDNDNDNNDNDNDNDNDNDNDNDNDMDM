"""Bot-only RENZ/7NET regression and positive synthetic cryptographic fixtures."""
from __future__ import annotations

import base64
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from decoders.Python import renz
from spdecode.registry import DECODER_REGISTRY, get_supported_extension, validate_decoder_files

ROOT = Path(__file__).resolve().parents[1]


def xxtea_encrypt(payload: bytes, key: bytes, vpn: str = "") -> bytes:
    """Inverse of the original RENZ custom XXTEA rounds; fixture generator only."""
    delta, offset = renz.RENZ_DELTA_V2, renz.RENZ_OFFSET_V2
    if vpn == "tcxtunnel":
        delta, offset = 0x9E3779B9, 0x4AB325AA
    words = renz.renz_xxtea_to_uint32(payload, True)
    n = len(words)
    if n < 2:
        raise ValueError("XXTEA synthetic fixture requires more than one word")
    k = renz.renz_prepare_key_xxtea(key)
    rounds = 52 // n + 6
    total = 0
    for _ in range(rounds):
        total = (total + delta) & 0xFFFFFFFF
        e = (total >> 2) & 3
        z = words[-1]
        for p in range(n - 1):
            y = words[p + 1]
            words[p] = (words[p] + renz.renz_mx(total, y, z, p, e, k)) & 0xFFFFFFFF
            z = words[p]
        words[-1] = (words[-1] + renz.renz_mx(
            total, words[0], z, n - 1, e, k)) & 0xFFFFFFFF
    assert total == ((52 // n) * delta - offset) & 0xFFFFFFFF
    return struct.pack("<%dI" % n, *words)


def profile_fixture(profile: str, config: dict) -> bytes:
    """Build a source-compatible CBC(XXTEA(JSON + 2)) RENZ export."""
    data = json.dumps(config, ensure_ascii=False).encode("utf-8")
    if profile in {"tcxtunnel", "trptunnel"}:
        key = bytes.fromhex(
            "6103102f3df a7cac1aa5b8ff4ba12022".replace(" ", "")
        ) if profile == "tcxtunnel" else bytes.fromhex("91f9eea7eb614fbbff2521e76306cea4")
        aes = AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16)
        encrypted = aes.encrypt(pad(data, 16))
        return base64.b64encode(xxtea_encrypt(encrypted, key, "tcxtunnel"))
    spec = renz.RENZ_KEYS[profile]
    key = hashlib.sha256(spec["KEY_SEED"]).digest()[:16]
    transformed = data if profile in {
        "xhypher", "safetunnel", "mhrtunnel", "letsvpngo"
    } else bytes((b + 2) & 255 for b in data)
    xxtea_data = xxtea_encrypt(transformed, key)
    cipher = AES.new(key, AES.MODE_CBC, iv=spec["IV"])
    return base64.b64encode(cipher.encrypt(pad(xxtea_data, 16)))


def threefish_encrypt256_block(key: bytes, tweak: tuple[int, int], data: bytes) -> bytes:
    """Inverse of the original 18-round Threefish block, for independent test input."""
    mask = 0xFFFFFFFFFFFFFFFF
    words = list(struct.unpack("<4Q", data))
    sub = renz.threefish_set_key(256, list(struct.unpack("<4Q", key)), list(tweak))
    for j in range(4):
        words[j] = (words[j] + sub[0][j]) & mask
    for group in range(18):
        for step in range(4):
            r0, r1 = renz.RENZ_THREEFISH256_ROTATIONS[(group * 4 + step) % 8]
            def mix(x0, x1, rotation):
                y0 = (x0 + x1) & mask
                y1 = (((x1 << rotation) | (x1 >> (64 - rotation))) & mask) ^ y0
                return y0, y1
            words[0], words[1] = mix(words[0], words[1], r0)
            words[2], words[3] = mix(words[2], words[3], r1)
            words = [words[i] for i in renz.RENZ_THREEFISH256_PERMUTE]
        for j in range(4):
            words[j] = (words[j] + sub[group + 1][j]) & mask
    return struct.pack("<4Q", *words)


def special_fixture(profile: str, clear: str) -> str:
    spec = renz.RENZ_KEYS[profile]
    key16 = renz.renz_generate_hkdf_key(spec["KEY_SEED"], spec["FIXED_SALT"])
    key32 = renz.renz_generate_hkdf32_key(spec["KEY_SEED"], spec["FIXED_SALT"])
    aes_blob = AES.new(key16, AES.MODE_CBC, iv=spec["IV"]).encrypt(
        pad(clear.encode("utf-8"), 16))
    # A complete Two-block (64-byte) or single-block (32-byte) stream.
    aes_blob += bytes(-len(aes_blob) % 32)
    cipher = bytearray()
    for offset in range(0, len(aes_blob), 32):
        i = offset // 32
        tweak1 = 0 if profile in {
            "7net", "actunnelvpn", "vipsnipherpro", "deshtunnelvpn", "hamotunnelplus"
        } else i * 64
        cipher.extend(threefish_encrypt256_block(
            key32, (i, tweak1), aes_blob[offset:offset + 32]))
    return base64.b64encode(cipher).decode("ascii")


class RenzFamilyTests(unittest.TestCase):
    def test_registered_16_new_bot_formats(self):
        self.assertEqual(len(renz.RENZ_FILE_EXTENSIONS), 16)
        self.assertEqual(len(set(DECODER_REGISTRY) - {'solid','1ftnl','awg','creeb'}), 239)
        for suffix, profile in renz.RENZ_FILE_EXTENSIONS.items():
            with self.subTest(suffix=suffix):
                self.assertIn(profile, renz.RENZ_KEYS)
                self.assertEqual(get_supported_extension("TEST" + suffix.upper()), suffix[1:])
                self.assertEqual(DECODER_REGISTRY[suffix[1:]].script,
                                 "decoders/Python/renz.py")
        self.assertEqual(DECODER_REGISTRY["vlx"].script, "decoders/Python/ultra.py")
        self.assertEqual(validate_decoder_files(), [])

    def test_all_16_extensions_positive_with_correct_profile(self):
        original = {"Server": "test.invalid", "Port": 443, "Enabled": False,
                    "Notes": "Prueba 日本語", "Modes": ["SSH", "V2Ray"]}
        cache = {}
        for ext, profile in renz.RENZ_FILE_EXTENSIONS.items():
            if profile not in cache:
                cache[profile] = profile_fixture(profile, original)
            with self.subTest(ext=ext, profile=profile):
                result = renz.decode_file(cache[profile], ext)
                self.assertIsNotNone(result, ext)
                decoded = json.loads(result)
                self.assertEqual(decoded["extension"], ext)
                self.assertEqual(decoded["config"], original)

    def test_all_23_protocol_aliases(self):
        self.assertEqual(len(renz.RENZ_TEXT_PROTOCOLS), 23)
        doc = {"Host": "test.invalid", "Port": 443}
        cache = {}
        for scheme, profile in renz.RENZ_TEXT_PROTOCOLS.items():
            if profile not in cache:
                cache[profile] = profile_fixture(profile, doc).decode("ascii")
            with self.subTest(scheme=scheme):
                result = renz.decode_text(scheme.upper() + cache[profile])
                self.assertIsNotNone(result, scheme)
                parsed = json.loads(result)
                self.assertEqual(parsed["config"], doc)
                self.assertEqual(parsed["protocol"], scheme)

    def test_standalone_threefish_special_and_nested_host(self):
        field = special_fixture("7net", "edge.example.com")
        self.assertEqual(renz.renz_decrypt_speciale(field, "7net"), "edge.example.com")
        doc = {"Host": field, "Port": 22}
        result = renz.decode_file(profile_fixture("7net", doc), ".7net")
        self.assertIsNotNone(result)
        self.assertEqual(json.loads(result)["config"]["Host"], "edge.example.com")

    def test_type3_hkdf_aes_cbc_fallback_for_sevnet(self):
        doc = {"Server": "typed.example", "Version": 3, "Enabled": True}
        key = renz.renz_get_hkdf_key()
        iv = bytes(range(16))
        blob = iv + AES.new(key, AES.MODE_CBC, iv).encrypt(
            pad(json.dumps(doc).encode("utf-8"), 16))
        encoded = base64.b64encode(blob)
        result = renz.decode_file(encoded, ".osp")
        self.assertIsNotNone(result)
        self.assertEqual(json.loads(result)["config"], doc)

    def test_cli_and_invalid_file_errors(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.tcx"
            path.write_bytes(profile_fixture("tcxtunnel", {"Host": "tcx.invalid"}))
            proc = subprocess.run(
                [sys.executable, str(ROOT / "decoders/Python/renz.py"), str(path)],
                cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(proc.stdout)["config"]["Host"], "tcx.invalid")

            path.write_bytes(b"not a real ciphertext")
            proc = subprocess.run(
                [sys.executable, str(ROOT / "decoders/Python/renz.py"), str(path)],
                cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 1)
            self.assertFalse(proc.stdout.strip())

    def test_bad_payload_wrong_scheme_and_out_of_scope_suffix(self):
        self.assertIsNone(renz.decode_file(b"", ".7net"))
        self.assertIsNone(renz.decode_file(b"broken base64", ".7net"))
        self.assertIsNone(renz.decode_file(b"A" * (renz.MAX_INPUT_BYTES + 1), ".7net"))
        self.assertIsNone(renz.decode_file(b"broken", ".vlx"))
        self.assertIsNone(renz.decode_text("vlx://abcd"))
        self.assertIsNone(renz.decode_text("izph://abcd"))
        self.assertIsNone(renz.decode_text("7net://not-valid"))
        self.assertIsNone(renz.decode_file(b"tcx://abc", ".7net"))


if __name__ == "__main__":
    unittest.main()
