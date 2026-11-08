"""Synthetic cross-reference tests: never execute APK code or research scripts."""
from __future__ import annotations
import unittest
from cloud.apk_analysis.qa_tool_harness import inspect_harness


class HarnessTests(unittest.TestCase):
    def test_correlates_dex_and_jadx_without_claiming_decryption(self):
        dex = {"dexHeaders": [{"tableStatus": "PARSED",
            "candidateMethods": [{"class": "Lcom/owned/Cripto;", "name": "decrypt"}],
            "methodCodeEvidence": [{"class": "Lcom/owned/Cripto;",
                "status": "CODE_ITEM_HASHED", "bytecodeSha256": "0"*64}]}],
            "nativeLibraries": [{"sectionStatus": "PARSED"}]}
        tools = {"jadxAttempted": True, "jadx": {"candidateCallSites": [
            {"class": "com.owned.Cripto", "method": "m948", "indicator": "JCA_CIPHER"},
            {"class": "org.conscrypt.OpenSSLCipher", "method": "a", "indicator": "JCA_CIPHER"}]}}
        report = inspect_harness(dex, tools)
        self.assertEqual(report["catalogue"]["registeredResearchScripts"], 63)
        self.assertEqual(report["catalogue"]["researchScriptsAutoExecuted"], 0)
        self.assertEqual(report["candidateClasses"][0]["class"], "com.owned.Cripto")
        self.assertIn("JADX_REFERENCE", report["candidateClasses"][0]["evidence"])
        self.assertIn("DEX_CODE_ITEM_SHA256", report["candidateClasses"][0]["evidence"])
        self.assertFalse(report["methodValidated"])
        self.assertFalse(report["codeExecuted"])
        self.assertNotIn("org.conscrypt", str(report))

    def test_bounded_even_for_many_candidates(self):
        dex={"dexHeaders": [{"candidateMethods": [
            {"class": f"Lcom/owned/C{i};", "name": "decrypt"} for i in range(80)
        ]}]}
        report=inspect_harness(dex, {"jadx": {}})
        self.assertLessEqual(len(report["candidateClasses"]), 24)
        self.assertTrue(report["candidateClassesTruncated"])


if __name__=="__main__":
    unittest.main()
