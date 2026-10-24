"""SP-DECODE Phase H audit tests; no false real-device or public-release claims."""
from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from scripts.android_h_production_audit import inspect
from scripts.android_release_gate import check

ROOT = Path(__file__).resolve().parents[1]


class PhaseHProductionAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Audit the actual declared version instead of a frozen prior build.
        # inspect() independently validates the version/code and NO-GO release gate.
        cls.data = inspect()

    def test_source_inventory_still_exactly_239(self):
        self.assertEqual(self.data["sourceGate"], "PASS",
                         {k:v for k,v in self.data["sourceChecks"].items() if not v["pass"]})
        catalog=self.data["catalog"]
        self.assertEqual(catalog["suffixes"], 239)
        self.assertEqual(catalog["nativePortRoutes"], 239)
        self.assertEqual(catalog["certifiedCurrentExporterSuffixes"], 0)
        self.assertEqual(catalog["byPhase"],
             {"legacy":61,"B":81,"C":41,"D":16,"E":27,"F":13})

    def test_offline_and_signing_are_explicitly_enforced(self):
        checks=self.data["sourceChecks"]
        for name in ("source_manifest_offline","history_backup_disabled",
            "permanent_signing_only","release_sha_and_main_only",
            "v1v2v3_and_alignment","all_golden_generators_ci"):
            with self.subTest(check=name):self.assertTrue(checks[name]["pass"])

    def test_no_unverified_real_exporter_is_claimed_certified(self):
        self.assertTrue(self.data["assertions"]["no_real_vendor_exporters_claimed"])
        self.assertEqual(self.data["productionGate"],"NO-GO")
        self.assertGreaterEqual(len(self.data["pendingEvidence"]),8)
        flags={row["gate"] for row in self.data["pendingEvidence"]}
        self.assertIn("realExporterFormats",flags)
        self.assertIn("signingInstallUpgrade",flags)
        self.assertIn("real_text_protocol_version_matrix",flags)

    def test_previous_owner_approval_does_not_transfer_to_play_beta(self):
        readiness=json.loads((ROOT/"release/android-readiness.json").read_text("utf-8"))
        self.assertEqual(readiness["stableVersion"],self.data["targetVersion"])
        self.assertGreaterEqual(self.data["targetVersionCode"],30)
        self.assertEqual(readiness["decision"],"NO-GO")
        self.assertFalse(readiness["ownerApproval"])
        self.assertFalse(readiness["publicPreviewApproval"])
        self.assertFalse(readiness["ownerStableAcceptance"]["approved"])
        self.assertEqual(self.data["productionGate"],"NO-GO")
        self.assertTrue(check(readiness,"stable",self.data["targetVersion"]))
        self.assertTrue(check(readiness,"public-preview",self.data["targetVersion"]))
        prior=copy.deepcopy(readiness)
        prior.update({"stableVersion":"1.1.4","decision":"OWNER-GO","ownerApproval":True})
        prior["ownerStableAcceptance"]={
            "approved":True,"version":"1.1.4",
            "report":"docs/android/RELEASE_1_1_4_PRODUCTION.md",
        }
        self.assertEqual([],check(prior,"stable","1.1.4"))
        self.assertTrue(check(prior,"stable",self.data["targetVersion"]))
        self.assertTrue(check(prior,"public-preview","1.1.4"))
        self.assertEqual(0,self.data["catalog"]["certifiedCurrentExporterSuffixes"])

    def test_whatsnew_and_catalog_status_all_four_locales(self):
        for folder in ("values","values-es","values-pt-rBR","values-ar"):
            with self.subTest(locale=folder):
                path=ROOT/"android/app/src/main/res"/folder/"strings.xml"
                content=path.read_text("utf-8")
                self.assertIn("1.1.4",content)
                self.assertIn("239",content)
                self.assertNotIn("183 native",content)
                self.assertNotIn("56 pending",content)


if __name__ == "__main__":
    unittest.main()
