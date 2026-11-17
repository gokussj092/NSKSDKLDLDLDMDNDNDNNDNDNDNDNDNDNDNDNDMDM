"""Synthetic verification of the repo Hex Custom 10.6.7 decoder.

No real files, no real passwords, no network. Seals synthetic profiles
with the decoder itself and re-opens them through decode(), plus the
decoder's own 11/11 self-test.
"""
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
DECODER = ROOT / "decoders/Python/apps/Hex_Custom/Hex_Custom_10.6.7.py"


def load_decoder():
    spec = importlib.util.spec_from_file_location("_hc_10_6_7_verify", DECODER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROFILE = {
    "version": 1,
    "server": {
        "name": "synthetic-only",
        "host": "example.invalid",
        "port": 443,
        "username": "synthetic",
        "password": "",
    },
    "meta": {"blocked": False, "company": "SYNTHETIC", "country": "xx"},
}


class Verify107Tests(unittest.TestCase):
    def test_self_test_is_11_of_11(self):
        proc = subprocess.run(
            [sys.executable, str(DECODER), "--self-test"],
            capture_output=True, text=True, timeout=300, cwd="/tmp",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        last = proc.stdout.strip().splitlines()[-1]
        self.assertEqual(json.loads(last)["passed"], 11)

    def test_round_trip_without_password(self):
        module = load_decoder()
        sealed = module.seal(PROFILE)
        opened = module.decode(sealed)
        self.assertEqual(opened["server"]["name"], "synthetic-only")
        self.assertEqual(opened["meta"]["company"], "SYNTHETIC")

    def test_round_trip_with_password(self):
        module = load_decoder()
        sealed = module.seal(PROFILE, password="synthetic-test-only")
        self.assertEqual(
            module.decode(sealed, password="synthetic-test-only")["server"]["name"],
            "synthetic-only",
        )

    def test_wrong_password_and_missing_password_fail(self):
        module = load_decoder()
        sealed = module.seal(PROFILE, password="synthetic-test-only")
        with self.assertRaises(module.DecodeError) as failure:
            module.decode(sealed, password="wrong-synthetic")
        self.assertEqual(failure.exception.code, "WRONG_PASSWORD")
        with self.assertRaises(module.DecodeError) as failure:
            module.decode(sealed)
        self.assertEqual(failure.exception.code, "PASSWORD_REQUIRED")

    def test_tampered_file_fails(self):
        module = load_decoder()
        sealed = bytearray(module.seal(PROFILE))
        sealed[-1] ^= 1
        with self.assertRaises(module.DecodeError):
            module.decode(bytes(sealed))


if __name__ == "__main__":
    unittest.main()
