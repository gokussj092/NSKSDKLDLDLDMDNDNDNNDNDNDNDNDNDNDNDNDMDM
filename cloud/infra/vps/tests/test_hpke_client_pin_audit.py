"""Regression tests for Android public pin / running web HPKE audit."""
import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
AUDIT = ROOT / "cloud/infra/vps/hpke-client-pin-audit.py"
spec = importlib.util.spec_from_file_location("hpke_client_pin_audit", AUDIT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class HpkePinAuditTests(unittest.TestCase):
    def test_native_public_pin_is_stable_and_self_consistent(self):
        # This is a public ID, not a private X25519 key.
        self.assertEqual(audit.expected_key_id(), "896f195624217d42")

    def test_missing_and_corrupted_pin_sources_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            p = pathlib.Path(temp) / "pin.cpp"
            p.write_text("no key", encoding="utf-8")
            with self.assertRaises(ValueError):
                audit.expected_key_id(p)
            p.write_text(audit.NATIVE.read_text("utf-8").replace("0x4d, 0xd5", "0x4e, 0xd5", 1),encoding="utf-8")
            with self.assertRaises(ValueError):
                audit.expected_key_id(p)


if __name__ == "__main__":
    unittest.main()
