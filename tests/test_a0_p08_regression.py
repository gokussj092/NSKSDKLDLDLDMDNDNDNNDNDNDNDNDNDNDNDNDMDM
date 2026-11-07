"""F7-A0-P08 safety and reporting tests. Never execute vendor tools or network."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from scripts.ci import run_a0_p08_regression as p08


class P08RegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.matrix = json.loads((cls.root / p08.MATRIX).read_text("utf-8"))

    def variants(self):
        return copy.deepcopy(self.matrix)

    def test_matrix_has_five_formats_and_original_consumers(self):
        suites = p08.validate_matrix(self.variants(), self.root)
        self.assertEqual(len(suites), 19)
        self.assertEqual({s["format"] for s in suites}, set(p08.REQUIRED_FORMATS))
        self.assertEqual({s["consumer"] for s in suites},
                         set(p08.REQUIRED_CONSUMERS))

    def test_gate_checks_sources_without_executing_methods(self):
        result = p08.audit(self.root, check_only=True)
        self.assertEqual(result["status"], "CHECK_ONLY")
        self.assertEqual(result["tested_suite_count"], 0)
        self.assertFalse(result["verification"]["existing_code_executed_with_offline_fixtures"])
        self.assertFalse(result["verification"]["real_vendor_apk"])
        self.assertTrue(result["protected_sources_unchanged_during_test"])
        self.assertGreater(result["sources_checked"], 63)

    def test_cannot_omit_existing_test_suite(self):
        matrix = self.variants()
        matrix["suites"].pop()
        with self.assertRaises(p08.RegressionConfigError):
            p08.validate_matrix(matrix, self.root)

    def test_cannot_add_duplicate_or_unknown_suite(self):
        matrix = self.variants()
        matrix["suites"][1] = matrix["suites"][0]
        with self.assertRaises(p08.RegressionConfigError):
            p08.validate_matrix(matrix, self.root)

    def test_cannot_reduce_minimum_case_count(self):
        matrix = self.variants()
        matrix["suites"][0]["min_tests"] = 0
        with self.assertRaises(p08.RegressionConfigError):
            p08.validate_matrix(matrix, self.root)

    def test_cannot_rename_executable_test_module(self):
        matrix = self.variants()
        matrix["suites"][0]["test_module"] = "tests.test_dummy"
        with self.assertRaises(p08.RegressionConfigError):
            p08.validate_matrix(matrix, self.root)

    def test_cannot_claim_real_vendor_from_synthetic_fixtures(self):
        matrix = self.variants()
        matrix["real_vendor_apk_verified"] = True
        with self.assertRaises(p08.RegressionConfigError):
            p08.validate_matrix(matrix, self.root)
        matrix = self.variants()
        matrix["suites"][3]["claims_real_vendor_verified"] = True
        with self.assertRaises(p08.RegressionConfigError):
            p08.validate_matrix(matrix, self.root)

    def test_source_traversal_and_unknown_sources_rejected(self):
        matrix = self.variants()
        matrix["suites"][2]["code_paths"] = ["../secrets.py"]
        with self.assertRaises(p08.RegressionConfigError):
            p08.validate_matrix(matrix, self.root)
        matrix = self.variants()
        matrix["suites"][2]["code_paths"] = ["cloud/workers/python/does_not_exist.py"]
        with self.assertRaises(p08.RegressionConfigError):
            p08.validate_matrix(matrix, self.root)

    def test_cannot_reduce_required_format_coverage(self):
        matrix = self.variants()
        matrix["required_formats"].remove("catalog")
        with self.assertRaises(p08.RegressionConfigError):
            p08.validate_matrix(matrix, self.root)
        matrix = self.variants()
        matrix["suites"][0]["format"] = "catalog"
        with self.assertRaises(p08.RegressionConfigError):
            p08.validate_matrix(matrix, self.root)

    def test_python_unittest_result_parser_and_skips(self):
        self.assertEqual(p08.parse_result("python", "Ran 12 tests in 0.023s\n\nOK"),
                         (12, 12, 0))
        self.assertEqual(p08.parse_result("python",
                                         "Ran 4 tests in 0.001s\n\nOK (skipped=1)"),
                         (4, 3, 1))

    def test_node_tap_result_parser_and_skips(self):
        out = "# tests 8\n# pass 8\n# fail 0\n# skipped 0\n"
        self.assertEqual(p08.parse_result("node", out), (8, 8, 0))
        self.assertEqual(p08.parse_result("node", out.replace("# skipped 0",
                                                               "# skipped 2")), (8, 8, 2))
        self.assertEqual(p08.parse_result("node", "unexpected failure"), (0, 0, 0))

    def test_runtime_failure_is_not_reported_as_pass(self):
        suite = self.variants()["suites"][0]
        with patch.object(p08.subprocess, "run", return_value=subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="Ran 1 test in 0.01s\nFAILED")):
            result = p08.run_suite(self.root, suite, 3)
        self.assertNotEqual(result["status"], "PASS")
        self.assertNotIn("stderr", result)
        self.assertNotIn("stdout", result)

    def test_skipped_runtime_test_fails_closed(self):
        suite = self.variants()["suites"][0]
        with patch.object(p08.subprocess, "run", return_value=subprocess.CompletedProcess(
                args=[], returncode=0, stdout="",
                stderr="Ran 1 test in 0.01s\nOK (skipped=1)")):
            result = p08.run_suite(self.root, suite, 3)
        self.assertNotEqual(result["status"], "PASS")

    def test_source_mutation_is_detected(self):
        with patch.object(p08, "source_hashes", side_effect=[
                {"decoders/Python/a.py": "before"},
                {"decoders/Python/a.py": "after"}]), patch.object(
                p08, "run_suite", return_value={
                    "status": "PASS", "executed_cases": 10}):
            result = p08.audit(self.root, runtime="python")
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["changed_source_paths_during_test"],
                         ["decoders/Python/a.py"])

    def test_python_runtime_cannot_run_without_explicit_opt_in(self):
        with self.assertRaises(p08.RegressionConfigError):
            p08.audit(self.root)

    def test_offline_fixture_status_never_certifies_live_apk(self):
        with patch.object(p08, "source_hashes", return_value={}), patch.object(
                p08, "run_suite", return_value={
                    "status": "PASS", "executed_cases": 10}):
            result = p08.audit(self.root, runtime="python")
        self.assertFalse(result["verification"]["real_vendor_apk"])
        self.assertFalse(result["verification"]["real_vendor_endpoint"])
        self.assertFalse(result["verification"]["approval_for_unattended_tools"])


if __name__ == "__main__":
    unittest.main()
