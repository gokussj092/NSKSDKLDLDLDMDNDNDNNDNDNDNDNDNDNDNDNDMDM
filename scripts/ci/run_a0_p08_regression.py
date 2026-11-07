#!/usr/bin/env python3
"""F7-A0-P08: run selected existing regression suites against UNMODIFIED sources.

This tool never downloads APKs, treats synthetic fixtures as vendor proof, edits
decoders, or changes a method's approval state. Python suites run in Validate;
Node/Cloud API suites run in the existing Cloud C6 job after npm install.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
MATRIX = "analysis/platform/apk-tooling/p08_regression_matrix.v1.json"
SOURCE_ROOTS = ("scripts/apk_analysis", "decoders/Python", "cloud/workers/python",
                "cloud/web/lib", "cloud/web/app/api")
EXTS = frozenset({".py", ".js", ".mjs", ".ts", ".tsx"})
REQUIRED_FORMATS = frozenset({"file", "text", "catalog", "export", "transport"})
REQUIRED_CONSUMERS = frozenset({"worker", "decoder", "cli", "export", "handler", "web"})
# Immutable minimum selection in code: editing the registry cannot silently
# drop coverage, rename a test or shrink its minimum. No past-version history.
REQUIRED = {
    "cloud-file-parity": ("python", "tests.test_cloud_c2_golden", 1),
    "cloud-hc-formats": ("python", "tests.test_cloud_c2_hc", 2),
    "cloud-text-protocols": ("python", "tests.test_cloud_c2_text", 2),
    "tls-ev2ray": ("python", "tests.test_current_decoders", 2),
    "server-catalog-worker": ("python", "tests.test_cloud_server_vpn_new", 4),
    "catnet-catalog": ("python", "tests.test_catnet_vpn", 12),
    "http-conexion-catalog": ("python", "tests.test_http_conexion", 10),
    "http-conexion-refresh": ("python", "tests.test_http_conexion_refresh", 8),
    "namo-catalog": ("python", "tests.test_namo_vpn", 15),
    "ha-unlocked-export": ("python", "tests.test_ha_catalog_export", 7),
    "c8-worker-bridge": ("python", "tests.test_cloud_c8_worker_integration", 10),
    "server-vpn-transport": ("python", "tests.test_cloud_server_vpn_transport", 2),
    "snapshot-and-chunks": ("node", "catalog-snapshots.test.mjs", 3),
    "server-catalog-route": ("node", "server-vpn-catalog.test.mjs", 5),
    "unlocked-web-policy": ("node", "compatible-export-policy.test.mjs", 3),
    "http-conexion-web": ("node", "http-conexion.test.mjs", 3),
    "xxpicore-web": ("node", "xxpicore-tunnel.test.mjs", 3),
    "c10-catalog-watch": ("node", "c10-catalog-push.test.mjs", 3),
    "catalog-edition-web": ("node", "catalog-edition.test.mjs", 1),
}


# The format/consumer attributed to each executed suite is part of the
# evidence contract. A registry-only label edit cannot fake coverage.
REQUIRED_LABELS = {
    "cloud-file-parity": ("file", "worker"),
    "cloud-hc-formats": ("file", "worker"),
    "cloud-text-protocols": ("text", "worker"),
    "tls-ev2ray": ("file", "decoder"),
    "server-catalog-worker": ("catalog", "worker"),
    "catnet-catalog": ("catalog", "cli"),
    "http-conexion-catalog": ("catalog", "cli"),
    "http-conexion-refresh": ("catalog", "cli"),
    "namo-catalog": ("catalog", "cli"),
    "ha-unlocked-export": ("export", "export"),
    "c8-worker-bridge": ("file", "worker"),
    "server-vpn-transport": ("transport", "handler"),
    "snapshot-and-chunks": ("catalog", "web"),
    "server-catalog-route": ("catalog", "web"),
    "unlocked-web-policy": ("export", "web"),
    "http-conexion-web": ("catalog", "web"),
    "xxpicore-web": ("catalog", "web"),
    "c10-catalog-watch": ("transport", "web"),
    "catalog-edition-web": ("catalog", "web"),
}


class RegressionConfigError(ValueError):
    pass


def safe_source_path(rel: str) -> bool:
    return (isinstance(rel, str)
            and not rel.startswith("/")
            and all(part not in {"", ".", ".."} for part in rel.split("/"))
            and rel.endswith(tuple(EXTS))
            and any(rel.startswith(parent + "/") for parent in SOURCE_ROOTS))


def validate_matrix(matrix: dict, root: Path) -> list[dict]:
    if not isinstance(matrix, dict) or matrix.get("schema_version") != 1:
        raise RegressionConfigError("P08 matrix schema is invalid")
    suites = matrix.get("suites")
    if not isinstance(suites, list) or len(suites) != len(REQUIRED):
        raise RegressionConfigError("P08 regression suite count changed")
    if (matrix.get("approval") != "NONE_GRANTED"
        or matrix.get("execution") != "CURRENT_PRODUCTION_CODE_WITH_OFFLINE_FIXTURES"
        or any(matrix.get(key) is not False for key in
               ("real_vendor_apk_verified", "real_vendor_endpoint_verified",
                "real_android_e2e_verified"))):
        raise RegressionConfigError("P08 cannot claim live vendor/API/APK verification")
    if (set(matrix.get("required_formats", [])) != REQUIRED_FORMATS
        or set(matrix.get("required_consumers", [])) != REQUIRED_CONSUMERS
        or matrix.get("minimum_suite_count") != len(REQUIRED)
        or matrix.get("minimum_total_cases", 0) < 90):
        raise RegressionConfigError("P08 declared format, consumer or suite coverage shrunk")
    by_id = {}
    for item in suites:
        if not isinstance(item, dict):
            raise RegressionConfigError("Invalid P08 suite record")
        ident = item.get("id")
        if ident not in REQUIRED or ident in by_id:
            raise RegressionConfigError("Unknown or duplicate P08 suite")
        runtime, target, minimum = REQUIRED[ident]
        target_field = "test_module" if runtime == "python" else "test_file"
        expected_path = (f"tests/{target.removeprefix('tests.').replace('.', '/')}.py"
                         if runtime == "python" else f"cloud/web/tests/{target}")
        # Python module is a single filename: tests.test_name -> tests/test_name.py
        if runtime == "python":
            expected_path = "tests/" + target.split(".")[-1] + ".py"
        paths = item.get("code_paths")
        if (item.get("runtime") != runtime
            or item.get(target_field) != target
            or item.get("min_tests", 0) < minimum
            or item.get("claims_real_vendor_verified") is not False
            or item.get("fixture_classification") != "SYNTHETIC_OR_SANITIZED_OFFLINE"
            or (item.get("format"), item.get("consumer")) != REQUIRED_LABELS[ident]
            or not isinstance(paths, list) or not paths or len(set(paths)) != len(paths)):
            raise RegressionConfigError("P08 suite contract changed: " + ident)
        if not (root / expected_path).is_file() or (root / expected_path).is_symlink():
            raise RegressionConfigError("Missing existing regression suite: " + ident)
        for p in paths:
            if not safe_source_path(p) or not (root / p).is_file() or (root / p).is_symlink():
                raise RegressionConfigError("Missing or invalid source path: " + ident)
        by_id[ident] = item
    if set(by_id) != set(REQUIRED):
        raise RegressionConfigError("P08 required regression suite missing")
    if ({v["format"] for v in suites} != REQUIRED_FORMATS
        or {v["consumer"] for v in suites} != REQUIRED_CONSUMERS
        or sum(x["min_tests"] for x in suites) < matrix["minimum_total_cases"]):
        raise RegressionConfigError("P08 coverage did not satisfy declared minimum")
    return [by_id[ident] for ident in REQUIRED]


def source_hashes(root: Path) -> dict[str, str]:
    result = {}
    for folder in SOURCE_ROOTS:
        source = root / folder
        if not source.is_dir() or source.is_symlink():
            raise RegressionConfigError("P08 protected source root not found: " + folder)
        for p in source.rglob("*"):
            if p.is_symlink():
                raise RegressionConfigError("P08 symlink inside protected source tree")
            if not p.is_file() or p.suffix not in EXTS:
                continue
            rel = p.relative_to(root).as_posix()
            result[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    return result


def parse_result(runtime: str, output: str) -> tuple[int, int, int]:
    if runtime == "python":
        found = re.search(r"\bRan (\d+) tests? in \d+(?:\.\d+)?s", output)
        executed = int(found.group(1)) if found else 0
        skipped = sum(int(v) for v in re.findall(r"\bskipped=(\d+)\b", output))
        failures = sum(int(v) for v in re.findall(r"\bfailures=(\d+)\b", output))
        errors = sum(int(v) for v in re.findall(r"\berrors=(\d+)\b", output))
        return executed, max(executed - skipped - failures - errors, 0), skipped
    found = re.search(r"(?m)^# tests (\d+)\s*$", output)
    passes = re.search(r"(?m)^# pass (\d+)\s*$", output)
    failures = re.search(r"(?m)^# fail (\d+)\s*$", output)
    skipped = re.search(r"(?m)^# skipped (\d+)\s*$", output)
    if not all((found, passes, failures, skipped)):
        return 0, 0, 0
    return int(found.group(1)), int(passes.group(1)), int(skipped.group(1))


def run_suite(root: Path, item: dict, timeout: int) -> dict:
    runtime, target, floor = REQUIRED[item["id"]]
    command = ([sys.executable, "-m", "unittest", "-v", target]
               if runtime == "python" else
               ["node", "--test", "tests/" + target])
    working_dir = root if runtime == "python" else root / "cloud/web"
    try:
        proc = subprocess.run(command, cwd=working_dir, capture_output=True, text=True,
                              errors="replace", timeout=timeout, check=False,
                              env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        count, passed, skipped = parse_result(runtime, proc.stdout + "\n" + proc.stderr)
        ok = (proc.returncode == 0 and count >= floor
              and passed == count and skipped == 0)
        code = ("PASS" if ok else
                "FAILED_OR_SKIPPED_OR_INSUFFICIENT_TESTS")
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        count = passed = skipped = 0
        code = "TIMEOUT"
        exit_code = None
    except FileNotFoundError:
        count = passed = skipped = 0
        code = "RUNTIME_NOT_INSTALLED"
        exit_code = None
    # Keep sanitized metadata only. Never attach stdout, ciphertext, tokens or APKs.
    return {"id": item["id"], "runtime": runtime, "format": item["format"],
            "consumer": item["consumer"], "source_paths": item["code_paths"],
            "minimum_cases": floor, "executed_cases": count, "passed_cases": passed,
            "skipped_cases": skipped, "exit_code": exit_code, "status": code,
            "verification_scope": "CURRENT_CODE_EXECUTED_WITH_OFFLINE_FIXTURES",
            "real_vendor_verified": False}


def audit(root: Path, *, runtime: str | None = None, check_only: bool = False,
          timeout: int = 180) -> dict:
    root = root.resolve()
    matrix = json.loads((root / MATRIX).read_text("utf-8"))
    suites = validate_matrix(matrix, root)
    before = source_hashes(root)
    executed = []
    if not check_only:
        if runtime not in ("python", "node"):
            raise RegressionConfigError("P08 execution requires --runtime python or node")
        executed = [run_suite(root, item, timeout) for item in suites
                    if item["runtime"] == runtime]
    after = source_hashes(root)
    unchanged = before == after
    failed = any(x["status"] != "PASS" for x in executed)
    return {
        "schema_version": 1,
        "scope": "F7_A0_P08_REGRESSION_WITH_EXISTING_PRODUCTION_CODE",
        "mode": "MATRIX_ONLY" if check_only else runtime,
        "status": "CHECK_ONLY" if check_only and unchanged else (
            "FAIL" if failed or not unchanged else "PASS"),
        "sources_checked": len(before),
        "protected_sources_unchanged_during_test": unchanged,
        "changed_source_paths_during_test": sorted(
            x for x in set(before) | set(after) if before.get(x) != after.get(x)),
        "selected_suites_total": len(suites),
        "selected_format_coverage": sorted({v["format"] for v in suites}),
        "selected_consumer_coverage": sorted({v["consumer"] for v in suites}),
        "tested_suite_count": len(executed),
        "tested_case_count": sum(x["executed_cases"] for x in executed),
        "results": executed,
        "verification": {
            "existing_code_executed_with_offline_fixtures": bool(executed),
            "real_vendor_apk": False, "real_vendor_endpoint": False,
            "android_to_cloud_e2e": False,
            "approval_for_unattended_tools": False,
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo-root", type=Path, default=ROOT)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--runtime", choices=["python", "node"])
    ap.add_argument("--check-only", action="store_true")
    ap.add_argument("--per-suite-timeout", type=int, default=180)
    args = ap.parse_args()
    if args.per_suite_timeout < 1 or args.per_suite_timeout > 600:
        print("P08: invalid timeout", file=sys.stderr)
        return 2
    try:
        report = audit(args.repo_root, runtime=args.runtime,
                       check_only=args.check_only, timeout=args.per_suite_timeout)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", "utf-8")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("P08 regression input error: " + type(exc).__name__, file=sys.stderr)
        return 2
    print("P08: mode={} status={} suites={} cases={} protected-sources={} unchanged={}"
          .format(report["mode"], report["status"], report["tested_suite_count"],
                  report["tested_case_count"], report["sources_checked"],
                  report["protected_sources_unchanged_during_test"]))
    for result in report["results"]:
        print("P08 SUITE {}: {} (pass={}/{} skip={})".format(
            result["id"], result["status"], result["passed_cases"],
            result["executed_cases"], result["skipped_cases"]))
    return 0 if report["status"] in {"PASS", "CHECK_ONLY"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
