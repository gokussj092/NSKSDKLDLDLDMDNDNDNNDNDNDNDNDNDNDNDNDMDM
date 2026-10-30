"""Offline regression test for missing trusted signer pins in Cloud APK builds."""
import importlib.util
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[2] / "scripts/ci/verify_release_signer_pins.py"
spec = importlib.util.spec_from_file_location("release_signer", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

A = "a" * 64
B = "b" * 64
SOURCE_OK = f'''public static final String TRUSTED_SIGNER_SHA256 = "{A}";
public static final String PLAY_APP_SIGNER_SHA256 = "{B}";'''
ENV_OK = {"SPDECODE_TRUSTED_SIGNER_SHA256": A,
          "SPDECODE_PLAY_APP_SIGNER_SHA256": B}

class SignedReleasePinTests(unittest.TestCase):
    def test_valid(self):
        module.validate(SOURCE_OK, ENV_OK)
    def test_missing_pin(self):
        with self.assertRaises(ValueError):
            module.validate(SOURCE_OK.replace(B, ""), ENV_OK)
    def test_blank_both(self):
        with self.assertRaises(ValueError):
            module.validate('TRUSTED_SIGNER_SHA256 = ""; PLAY_APP_SIGNER_SHA256 = "";', ENV_OK)
    def test_mismatched_pin(self):
        with self.assertRaises(ValueError):
            module.validate(SOURCE_OK, {**ENV_OK, "SPDECODE_TRUSTED_SIGNER_SHA256": B})
    def test_rejects_malformed(self):
        with self.assertRaises(ValueError):
            module.validate(SOURCE_OK, {**ENV_OK, "SPDECODE_PLAY_APP_SIGNER_SHA256": "x"})

if __name__ == "__main__":
    unittest.main()
