"""Prove JADX source summaries are evidence-bound and framework-noise filtered."""
from pathlib import Path
import tempfile
import unittest
from cloud.apk_analysis.qa_jadx_refs import scan_jadx_sources

class JadxReferenceTests(unittest.TestCase):
    def test_real_source_references_only_and_framework_excluded(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            own=root/"sources/com/example/vpn"
            own.mkdir(parents=True)
            (own/"ConfigCodec.java").write_text("""
              package com.example.vpn;
              class ConfigCodec {
                String decryptConfig(byte[] input) {
                  javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
                  SecretKeySpec key = new SecretKeySpec(input,"AES");
                  return "confidential-secret-never-exported";
                }
              }
            """)
            library=root/"sources/com/google/android/gms/security"
            library.mkdir(parents=True)
            (library/"Vendor.java").write_text("class Vendor { void encrypt(){ Cipher.getInstance(); } }")
            report=scan_jadx_sources(root)
            self.assertEqual(report["status"],"OBSERVED")
            self.assertIn("JCA_CIPHER",report["cryptoReferenceCounts"])
            self.assertIn("JCA_KEY_SPEC",report["cryptoReferenceCounts"])
            self.assertTrue(any(x["class"]=="com.example.vpn.ConfigCodec"
                                for x in report["candidateCallSites"]))
            self.assertFalse(any("google" in x["class"]
                                 for x in report["candidateCallSites"]))
            self.assertFalse(report["methodValidated"])
            self.assertNotIn("confidential-secret-never-exported",str(report))

    def test_oversized_generated_sources_do_not_exhaust_scanner(self):
        with tempfile.TemporaryDirectory() as folder:
            file=Path(folder)/"Big.java"
            file.write_text("A"*300_000)
            report=scan_jadx_sources(Path(folder))
            self.assertEqual(report["sourceFilesInspected"],1)
            self.assertEqual(report["skippedLargeOrUnsafe"],1)
            self.assertEqual(report["candidateCallSites"],[])

if __name__=="__main__":unittest.main()
