#!/usr/bin/env python3
"""F7-A0-P07 offline contract: required GitHub check wiring, not branch protection.

No network or token. Passing verifies local workflow wiring ONLY. Actual
required-check enforcement is a GitHub server-side repository setting.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ".github/workflows/f7-a0-method-evidence.yml"
REGISTRY = "analysis/platform/apk-tooling/legacy_provider_baseline.v1.json"
P06_SOURCE = "scripts/ci/check_a0_p06_coverage.py"
POLICY = "analysis/platform/apk-tooling/p07_required_checks.v1.json"


class CheckContractError(ValueError):
    pass


def audit(root: Path) -> dict:
    root = root.resolve()
    policy = json.loads((root / POLICY).read_text("utf-8"))
    registry = json.loads((root / REGISTRY).read_text("utf-8"))
    workflow = (root / WORKFLOW).read_text("utf-8")
    p06_source = (root / P06_SOURCE).read_text("utf-8")
    errors = []

    if (policy.get("schema_version") != 1
        or policy.get("target_branch") != "main"
        or policy.get("required_status_checks") != ["evidence-gate", "validate"]
        or policy.get("workflow") != "F7-A0 Method Evidence"
        or policy.get("job") != "evidence-gate"):
        errors.append("POLICY_CONTRACT_INVALID")
    if (not re.search(r"(?m)^name:\s*F7-A0 Method Evidence\s*$", workflow)
        or not re.search(r"(?m)^jobs:\s*$", workflow)
        or not re.search(r"(?m)^  evidence-gate:\s*$", workflow)):
        errors.append("REQUIRED_CHECK_JOB_MISSING_OR_RENAMED")
    event_part = workflow.split("\non:\n", 1)
    event_part = event_part[1].split("\npermissions:", 1)[0] if len(event_part) == 2 else ""
    pr = re.search(r"(?m)^  pull_request:\s*\n    branches:\s*\[([^\]]+)\]", event_part)
    if not pr or "main" not in [x.strip(" '\"") for x in pr.group(1).split(",")]:
        errors.append("PR_MAIN_EVENT_NOT_CONFIGURED")
    if re.search(r"(?m)^    (?:paths|paths-ignore):\s*", event_part):
        errors.append("PATH_FILTER_CAN_SKIP_REQUIRED_CHECK")
    # The job cannot be conditional: a required status must be emitted on
    # every PR targeting main, including doc-only changes.
    job_part = workflow.split("\n  evidence-gate:\n", 1)
    job_part = job_part[1] if len(job_part) == 2 else ""
    job_headers = re.search(r"(?m)^  [A-Za-z][\w-]*:\s*$", job_part)
    if job_headers:
        job_part = job_part[:job_headers.start()]
    if re.search(r"(?m)^    if:\s*", job_part):
        errors.append("REQUIRED_CHECK_JOB_CAN_BE_SKIPPED")
    if re.search(r"(?m)^\s+continue-on-error:\s*(?:true|yes)\s*$", job_part):
        errors.append("REQUIRED_CHECK_CAN_IGNORE_FAILURE")
    required_snippets = (
        "python -m unittest discover -s tests -p 'test_a0_p06_coverage.py'",
        "python -m unittest discover -s tests -p 'test_a0_p07_required_checks.py'",
        "python scripts/ci/check_a0_p06_coverage.py --enforce",
        "python scripts/ci/check_method_evidence.py --enforce",
        "PR_BASE_SHA:",
        "PR_HEAD_SHA:",
        "--legacy-cutover-ref",
        "if: github.event_name == 'pull_request'",
    )
    for part in required_snippets:
        if part not in job_part:
            errors.append("REQUIRED_GATE_STEP_MISSING:" + part)
    cutoff = registry.get("source_commit")
    if (not isinstance(cutoff, str)
        or not re.fullmatch("[0-9a-f]{40}", cutoff)
        or cutoff not in workflow
        or ('PINNED_CUTOVER_SHA = "' + cutoff + '"') not in p06_source):
        errors.append("CUTOFF_NOT_PINNED_IN_BOTH_GATE_AND_WORKFLOW")

    return {
        "schema_version": 1,
        "scope": "F7_A0_P07_OFFLINE_WORKFLOW_CONTRACT_ONLY",
        "workflow": WORKFLOW,
        "required_status_checks": policy.get("required_status_checks"),
        "target_branch": policy.get("target_branch"),
        "checks": {"workflow_wiring": "FAIL" if errors else "PASS",
                   "remote_branch_protection": "NOT_VALIDATED_BY_THIS_SCRIPT",
                   "blocking_merge": "NOT_ATTESTED"},
        "findings": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = audit(args.repo_root)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", "utf-8")
    except (OSError, ValueError, TypeError) as exc:
        print("P07 contract error: " + type(exc).__name__, file=sys.stderr)
        return 2
    print("P07 workflow contract: " + report["checks"]["workflow_wiring"]
          + "; GitHub branch protection NOT ATTESTED")
    for issue in report["findings"]:
        print("BLOCK: " + issue)
    return 1 if report["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
