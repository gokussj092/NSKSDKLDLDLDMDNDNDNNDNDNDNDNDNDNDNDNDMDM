"""Prove JADX source summaries are evidence-bound and framework-noise filtered."""
from pathlib import Path
import tempfile
import unittest
import os
from unittest import mock
from cloud.apk_analysis import qa_tooling
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

    def test_jadx_timeout_with_observed_sources_is_a_real_partial_not_success(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"authorized.apk"
            path.write_bytes(b"fixture")
            references={
                "status":"OBSERVED","sourceFilesInspected":2493,
                "sourceBytesInspected":3152472,"skippedLargeOrUnsafe":1,
                "candidateCallSites":[{"class":"example.C","indicator":"ANDROID_BASE64",
                    "method":"b","verifiedCryptoMethod":False}],
                "methodValidated":False,
            }
            with mock.patch.dict(os.environ, {
                "SPDECODE_APK_QA_TOOLS_REMOTE":"disabled",
                "SPDECODE_APK_QA_TOOL_MODE":"enabled",
                "SPDECODE_APK_QA_TOOLS_REVIEWED":"true",
                "SPDECODE_APK_QA_LITE":"true",
            }), mock.patch.object(qa_tooling,"_memory_limit",return_value=2**31), \
                    mock.patch.object(qa_tooling,"_verified_jadx",return_value=True), \
                    mock.patch.object(qa_tooling,"_base_and_libs",
                        return_value=(path,[],0,0)), \
                    mock.patch.object(qa_tooling,"_run_jadx",return_value="TIMEOUT"), \
                    mock.patch.object(qa_tooling,"scan_jadx_sources",
                        return_value=references.copy()):
                result=qa_tooling.inspect_tooling(path,{})
            self.assertEqual(result["status"],"TOOLS_PARTIAL")
            self.assertEqual(result["jadx"]["status"],"PARTIAL_OUTPUT")
            self.assertEqual(result["jadx"]["referenceScanStatus"],"OBSERVED")
            self.assertEqual(result["jadx"]["terminationReason"],"TIMEOUT")
            self.assertEqual(result["jadx"]["sourceFilesInspected"],2493)
            self.assertTrue(result["jadxAttempted"])
            self.assertFalse(result["jadxExecuted"])
            self.assertFalse(result["ghidraExecuted"])
            self.assertEqual(result["ghidra"]["status"],"DISABLED_IN_LITE_PROFILE")


if __name__=="__main__":unittest.main()
