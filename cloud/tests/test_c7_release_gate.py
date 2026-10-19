"""Prevent mislabeling synthetic parity as Android or Play certification."""
import json
import unittest
from scripts.cloud_c7_release_gate import LEDGER,REQUIRED,check
class ReleaseGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=json.loads(LEDGER.read_text(encoding="utf8"))
    def test_stage_ledger_has_all_evidence_fields(self):
        allowed,pending=check(self.data)
        self.assertTrue(allowed)
        self.assertEqual(len(REQUIRED),13)
        self.assertGreater(len(pending),0)
    def test_actual_devices_and_provider_compatibility_are_unverified(self):
        state={x["id"]:x["status"] for x in self.data["evaluations"]}
        for name in ["google_play_integrity_live","android_real_device_full_flow",
                     "exporter_version_matrix","staging_https_vps"]:
            self.assertEqual(state[name],"not_verified")
    def test_production_blocked_even_if_evidence_is_not_reviewed(self):
        allowed,pending=check(self.data,production=True)
        self.assertFalse(allowed)
        self.assertFalse(self.data["productionApproved"])
    def test_evidence_ledger_rejects_duplicate_or_missing_checks(self):
        fake=json.loads(json.dumps(self.data))
        fake["evaluations"].append(fake["evaluations"][0])
        with self.assertRaises(AssertionError):check(fake)
if __name__=="__main__":unittest.main()
