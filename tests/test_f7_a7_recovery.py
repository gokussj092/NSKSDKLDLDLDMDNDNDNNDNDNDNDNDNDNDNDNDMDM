"""F7-A7: deterministic recovery, report and deny-by-default tool contracts.

Synthetic fixtures prove orchestration only; no third-party APK is used.
"""
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

from cloud.apk_analysis.qa_jadx_recovery import (
    diagnose_termination, extract_dex_candidates, recover_jadx,
)
from cloud.apk_analysis.qa_tool_plan import INVENTORY, plan_tools, correlate_evidence
from cloud.apk_analysis import qa_tooling


class RecoveryTests(unittest.TestCase):
    def make_apk(self, folder, count=2):
        apk = Path(folder) / "owned.apk"
        with zipfile.ZipFile(apk, "w") as z:
            for i in range(count):
                name = "classes.dex" if i == 0 else "classes" + str(i + 1) + ".dex"
                z.writestr(name, b"dex\n035\0" + b"\0" * 128)
            z.writestr("asset/../../unsafe.dex", b"should-not-extract")
        return apk

    def test_diagnostic_is_bounded_codes_only_no_raw_log(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "jadx.log"
            p.write_bytes(b"personal_secret_123 OutOfMemoryError: Java heap space")
            self.assertEqual(diagnose_termination(p, "EXIT_NONZERO"), "JAVA_HEAP_EXHAUSTED")
            self.assertEqual(diagnose_termination(p, "TIMEOUT"), "TIME_LIMIT_EXCEEDED")
            self.assertEqual(diagnose_termination(p, "START_FAILED"), "PROCESS_START_FAILED")
            self.assertNotIn("personal_secret_123", diagnose_termination(p, "EXIT_NONZERO"))

    def test_extracts_only_bounded_root_dex_names(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            apk = self.make_apk(td, 6)
            inputs, info = extract_dex_candidates(apk, root)
            self.assertEqual(len(inputs), 4)
            self.assertEqual(info["dexDiscovered"], 6)
            self.assertEqual(info["dexSkipped"], 2)
            self.assertEqual(info["dexTooLarge"], 0)
            self.assertEqual([x.name for x in inputs], [
                "recovery-0.dex", "recovery-1.dex", "recovery-2.dex", "recovery-3.dex"])
            self.assertFalse((root / "unsafe.dex").exists())

    def test_corrupt_zip_is_recorded_not_promoted_to_success(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bad = root / "broken.apk"
            bad.write_bytes(b"corrupt")
            inputs, info = extract_dex_candidates(bad, root)
            self.assertFalse(inputs)
            self.assertEqual(info["extractionStatus"], "EXTRACTION_FAILED")

    def test_fallback_is_sequential_and_only_retries_failed_dex(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            apk = self.make_apk(td, 2)
            calls = []
            def fake_run(command, *, cwd, timeout, env, logfile):
                mode = command[command.index("--decompilation-mode") + 1]
                calls.append((mode, timeout))
                logfile.write_bytes(b"unsupported on primary")
                output = Path(command[command.index("-d") + 1])
                if mode == "fallback":
                    p = output / "sources" / "com" / "local"
                    p.mkdir(parents=True)
                    (p / "Owned.java").write_text(
                        "class Owned { void decrypt() { Cipher.getInstance(\"AES\"); } }")
                return "EXIT_ZERO" if mode == "fallback" else "EXIT_NONZERO"
            from cloud.apk_analysis.qa_jadx_refs import scan_jadx_sources
            result = recover_jadx(apk, root, Path("/not-needed.jar"), {},
                                  fake_run, scan_jadx_sources)
            self.assertEqual(calls, [("simple", 75), ("fallback", 75)] * 2)
            self.assertEqual(result["dexRecovered"], 2)
            self.assertEqual(result["dexDiscovered"], 2)
            self.assertGreater(result["sourceFilesInspected"], 0)
            self.assertFalse(result["methodValidated"])
            self.assertTrue(all(a["mode"] in ("simple", "fallback")
                                for a in result["attempts"]))

    def test_worker_failure_keeps_recovered_evidence_but_not_completion(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            apk = self.make_apk(td, 1)
            def fake_run(command, *, cwd, timeout, env, logfile):
                mode = command[command.index("--decompilation-mode") + 1]
                logfile.write_bytes(b"generic decompiler failure")
                output = Path(command[command.index("-d") + 1])
                if mode == "fallback":
                    p = output / "sources" / "com" / "owned"
                    p.mkdir(parents=True)
                    (p / "Owned.java").write_text(
                        "public class Owned { void decrypt() { Cipher.getInstance(\"AES\"); } }")
                    return "EXIT_ZERO"
                return "EXIT_NONZERO"
            with mock.patch.dict(os.environ, {
                    "SPDECODE_APK_QA_TOOLS_REMOTE": "disabled",
                    "SPDECODE_APK_QA_TOOL_MODE": "enabled",
                    "SPDECODE_APK_QA_TOOLS_REVIEWED": "true",
                    "SPDECODE_APK_QA_LITE": "true",
                    "SPDECODE_APK_QA_GHIDRA": "disabled",
            }), mock.patch.object(qa_tooling, "_memory_limit", return_value=2**31), \
                 mock.patch.object(qa_tooling, "_verified_jadx", return_value=True), \
                 mock.patch.object(qa_tooling, "_base_and_libs",
                                   return_value=(apk, [], 0, 0)), \
                 mock.patch.object(qa_tooling, "_run_jadx", side_effect=fake_run):
                result = qa_tooling.inspect_tooling(apk, {})
            self.assertEqual(result["status"], "TOOLS_PARTIAL")
            self.assertFalse(result["jadxExecuted"])
            self.assertEqual(result["jadx"]["status"], "PARTIAL_OUTPUT")
            self.assertEqual(result["jadx"]["recovery"]["dexRecovered"], 1)
            self.assertGreater(result["jadx"]["sourceFilesInspected"], 0)
            self.assertFalse(result["jadx"]["methodValidated"])
            self.assertEqual(result["ghidra"]["status"], "DISABLED_IN_LITE_PROFILE")

    def test_sixty_three_scripts_stay_unreviewed_and_not_executed(self):
        self.assertEqual(len(INVENTORY), 63)
        self.assertEqual(len(set(INVENTORY)), 63)
        sample = {
            "dexHeaders": [{"tableStatus": "PARSED", "candidateMethods": []}],
            "nativeLibraries": [{"sectionStatus": "PARSED", "architecture": "AARCH64"}],
        }
        plan = plan_tools(sample)
        self.assertEqual(plan["sourceLanguages"], {"python": 61, "javascript": 2})
        self.assertEqual(plan["automaticallyExecutedScripts"], 0)
        self.assertTrue(plan["reviewCandidates"])
        self.assertTrue(all(x["status"] == "CANDIDATE_REVIEW_REQUIRED"
                            and not x["executed"] for x in plan["reviewCandidates"]))
        graph = correlate_evidence(sample, {"jadx": {"recovery": {"dexRecovered": 1}}})
        self.assertFalse(graph["methodValidated"])
        self.assertEqual(graph["jadxRecoveredDexCount"], 1)


if __name__ == "__main__":
    unittest.main()
