"""F7-A0-P07: required status wiring unit tests; no GitHub credentials or network."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scripts.ci import check_a0_p07_required_check as p07

CUTOFF = "4fddee8924e58a9d1e6476974e9b7a9adda3e495"


class P07WorkflowContractTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.workflow = """name: F7-A0 Method Evidence

on:
  pull_request:
    branches: [main, feat/nuevas-integraciones]
  push:
    branches: [feat/nuevas-integraciones]

permissions:
  contents: read

jobs:
  evidence-gate:
    runs-on: ubuntu-latest
    steps:
      - name: P06 tests
        run: python -m unittest discover -s tests -p 'test_a0_p06_coverage.py'
      - name: P07 contract tests
        run: python -m unittest discover -s tests -p 'test_a0_p07_required_checks.py'
      - name: Enforce P06
        if: github.event_name == 'pull_request'
        env:
          PR_BASE_SHA: fixture
          PR_HEAD_SHA: fixture
          P06_LEGACY_CUTOVER_SHA: """ + CUTOFF + """
        run: python scripts/ci/check_a0_p06_coverage.py --enforce --base-ref "$PR_BASE_SHA" --pr-head-ref "$PR_HEAD_SHA" --legacy-cutover-ref "$P06_LEGACY_CUTOVER_SHA"
      - name: Enforce dossier gate
        if: github.event_name == 'pull_request'
        run: python scripts/ci/check_method_evidence.py --enforce --base-ref "$PR_BASE_SHA"
"""
        self.policy = {"schema_version": 1, "target_branch": "main",
                       "workflow": "F7-A0 Method Evidence", "job": "evidence-gate",
                       "required_status_checks": ["evidence-gate", "validate"]}
        self.registry = {"schema_version": 1, "source_commit": CUTOFF}
        self.write(p07.WORKFLOW, self.workflow)
        self.write(p07.POLICY, json.dumps(self.policy))
        self.write(p07.REGISTRY, json.dumps(self.registry))
        self.write(p07.P06_SOURCE, 'PINNED_CUTOVER_SHA = "' + CUTOFF + '"\n')

    def write(self, path, content):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, "utf-8")

    def violations(self):
        return p07.audit(self.root)["findings"]

    def test_valid_contract_still_does_not_claim_required_protection(self):
        report = p07.audit(self.root)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["checks"]["blocking_merge"], "NOT_ATTESTED")
        self.assertEqual(report["checks"]["remote_branch_protection"],
                         "NOT_VALIDATED_BY_THIS_SCRIPT")

    def test_job_renaming_blocked(self):
        self.write(p07.WORKFLOW, self.workflow.replace("  evidence-gate:", "  silently-other:"))
        self.assertIn("REQUIRED_CHECK_JOB_MISSING_OR_RENAMED", self.violations())

    def test_main_pr_trigger_missing_blocked(self):
        self.write(p07.WORKFLOW, self.workflow.replace("branches: [main, feat/nuevas-integraciones]",
                                                       "branches: [feat/nuevas-integraciones]"))
        self.assertIn("PR_MAIN_EVENT_NOT_CONFIGURED", self.violations())

    def test_path_filtered_pr_workflow_blocked(self):
        self.write(p07.WORKFLOW, self.workflow.replace("  push:\n", "    paths: ['decoders/**']\n  push:\n"))
        self.assertIn("PATH_FILTER_CAN_SKIP_REQUIRED_CHECK", self.violations())

    def test_required_job_cannot_be_conditional(self):
        self.write(p07.WORKFLOW, self.workflow.replace("    runs-on:", "    if: false\n    runs-on:"))
        self.assertIn("REQUIRED_CHECK_JOB_CAN_BE_SKIPPED", self.violations())

    def test_continue_on_error_cannot_hide_failures(self):
        self.write(p07.WORKFLOW, self.workflow.replace("    steps:", "    continue-on-error: true\n    steps:"))
        self.assertIn("REQUIRED_CHECK_CAN_IGNORE_FAILURE", self.violations())

    def test_must_enforce_p06(self):
        self.write(p07.WORKFLOW,
                   self.workflow.replace("python scripts/ci/check_a0_p06_coverage.py --enforce",
                                         "python scripts/ci/check_a0_p06_coverage.py"))
        self.assertTrue(any(x.startswith("REQUIRED_GATE_STEP_MISSING")
                            for x in self.violations()))

    def test_cutover_sha_mismatch_blocked(self):
        self.write(p07.P06_SOURCE, 'PINNED_CUTOVER_SHA = "' + "f" * 40 + '"\n')
        self.assertIn("CUTOFF_NOT_PINNED_IN_BOTH_GATE_AND_WORKFLOW", self.violations())

    def test_desired_status_contexts_cannot_be_silently_dropped(self):
        self.policy["required_status_checks"] = ["validate"]
        self.write(p07.POLICY, json.dumps(self.policy))
        self.assertIn("POLICY_CONTRACT_INVALID", self.violations())


if __name__ == "__main__":
    unittest.main()
