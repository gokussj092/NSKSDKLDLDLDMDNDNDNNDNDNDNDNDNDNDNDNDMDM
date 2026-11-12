#!/usr/bin/env python3
"""F7-A0: offline audit of research evidence and optional change gate.

This is a metadata auditor, never an APK runner or a decoder.
Only the Python standard library is used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

REQUIRED = ("MANIFEST.json", "ANALYSIS.md", "REPRODUCE.md", "RESULTS.md", "DEPENDENCIES.md")
LOCKS = ("dependencies.lock.json", "requirements.lock.txt", "requirements.txt", "poetry.lock", "uv.lock", "package-lock.json")
PROVIDER_PREFIX = "decoders/Python/apps/"
SHARED_PREFIX = "scripts/apk_analysis/"
GENERIC_METHOD_PATHS = {
    "cloud/workers/python/catalog_vpn_bridge.py",
    "cloud/web/lib/server-vpn-provider.mjs",
    "cloud/web/lib/server-vpn-gateway.mjs",
    "cloud/web/lib/server-vpn-catalog.mjs",
}


def hash_file(path: Path) -> dict:
    data = path.read_bytes()
    return {
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "git_blob_sha1": hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest(),
    }


def inside_repo_path(path: object) -> bool:
    if not isinstance(path, str) or not path or "\\" in path:
        return False
    p = PurePosixPath(path)
    return not p.is_absolute() and ".." not in p.parts and path == str(p)


def _strings(value: object):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for part in value.values():
            yield from _strings(part)
    elif isinstance(value, list):
        for part in value:
            yield from _strings(part)


def evidence_record(directory: Path, root: Path) -> dict:
    relative = directory.relative_to(root).as_posix()
    missing = [name for name in REQUIRED if not (directory / name).is_file()]
    if not any((directory / x).is_file() for x in LOCKS):
        missing.append("dependency lock/requirements")
    tools = [p for p in (directory / "tools").rglob("*") if p.is_file()] if (directory / "tools").is_dir() else []
    tests = [p for p in (directory / "tests").rglob("*") if p.is_file()] if (directory / "tests").is_dir() else []
    if not tools:
        missing.append("tools/*")
    if not tests:
        missing.append("tests/*")
    record = {"directory": relative, "missing": missing, "tools": len(tools), "tests": len(tests), "status": "UNKNOWN", "code_paths": []}
    manifest = directory / "MANIFEST.json"
    if not manifest.is_file():
        return record
    try:
        obj = json.loads(manifest.read_text("utf-8"))
    except (ValueError, UnicodeError) as exc:
        record["error"] = f"invalid MANIFEST.json: {type(exc).__name__}"
        return record
    if not isinstance(obj, dict):
        record["error"] = "MANIFEST.json must be an object"
        return record
    record["status"] = obj.get("status", "UNKNOWN")
    parts = PurePosixPath(relative).parts
    if len(parts) != 3 or parts[0] != "analysis" or not re.fullmatch(r"[A-Za-z0-9._-]+", parts[1]) or not re.fullmatch(r"[0-9]+", parts[2]):
        record["error"] = "non-canonical app/build path"
    elif obj.get("package_name") != parts[1] or str(obj.get("version_code")) != parts[2]:
        record["error"] = "package/version mismatch"
    for key in ("schema_version", "package_name", "version_code", "status", "targets", "tooling", "dependencies", "code_paths", "authorization_note"):
        if key not in obj:
            record.setdefault("invalid_fields", []).append(key)
    references = list(_strings(obj.get("code_paths", [])))
    record["code_paths"] = sorted(set(x for x in references if inside_repo_path(x)))
    if any(not inside_repo_path(x) for x in references):
        record.setdefault("invalid_fields", []).append("code_paths")
    if not isinstance(obj.get("dependencies"), list):
        record.setdefault("invalid_fields", []).append("dependencies")
    if not isinstance(obj.get("tooling"), list):
        record.setdefault("invalid_fields", []).append("tooling")
    if not isinstance(obj.get("targets"), list):
        record.setdefault("invalid_fields", []).append("targets")
    return record


def collect_evidence(root: Path) -> list[dict]:
    base = root / "analysis"
    found = []
    if not base.is_dir():
        return found
    for manifest in sorted(base.glob("*/*/MANIFEST.json")):
        if manifest.parts[-3] in ("_intake", "platform"):
            continue
        found.append(evidence_record(manifest.parent, root))
    return found


def collect_tools(root: Path) -> dict:
    path = root / SHARED_PREFIX
    tools = []
    if path.is_dir():
        for script in sorted(path.iterdir()):
            if script.is_file() and script.suffix in (".py", ".js"):
                tools.append({"path": script.relative_to(root).as_posix(), **hash_file(script), "approval": "UNREVIEWED"})
    req = path / "requirements.txt"
    packages = []
    if req.is_file():
        for line in req.read_text("utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                m = re.fullmatch(r"([\w.-]+)==([\w.+!-]+)", line)
                packages.append({"requirement": line, "pinned": bool(m), "review": "NEEDS_REVIEW"})
    return {"tools": tools, "requirements": packages, "runtime_approval": "NONE_GRANTED_BY_THIS_AUDIT"}


def check_snapshot(root: Path, tools: dict) -> list[dict]:
    snapshot = root / "analysis/platform/apk-tooling/tool_sources.v1.json"
    if not snapshot.is_file():
        return [{"code": "SNAPSHOT_MISSING", "path": snapshot.relative_to(root).as_posix()}]
    try:
        obj = json.loads(snapshot.read_text("utf-8"))
    except ValueError:
        return [{"code": "SNAPSHOT_INVALID_JSON"}]
    baseline = obj.get("sources")
    if obj.get("schema_version") != 1 or not isinstance(baseline, list):
        return [{"code": "SNAPSHOT_INVALID_SCHEMA"}]
    actual = {x["path"]: x for x in tools["tools"]}
    expected = {}
    problems = []
    for item in baseline:
        if not isinstance(item, dict) or not inside_repo_path(item.get("path")) or not re.fullmatch(r"[0-9a-f]{40}", str(item.get("git_blob_sha1", ""))):
            problems.append({"code": "SNAPSHOT_INVALID_ENTRY"})
            continue
        p = item["path"]
        if p in expected:
            problems.append({"code": "SNAPSHOT_DUPLICATE", "path": p})
        expected[p] = item
    for p in sorted(actual.keys() - expected.keys()):
        problems.append({"code": "UNREGISTERED_TOOL", "path": p})
    for p in sorted(expected.keys() - actual.keys()):
        problems.append({"code": "MISSING_REGISTERED_TOOL", "path": p})
    for p in sorted(expected.keys() & actual.keys()):
        if expected[p]["git_blob_sha1"] != actual[p]["git_blob_sha1"] or expected[p].get("size") != actual[p]["size"]:
            problems.append({"code": "TOOL_SOURCE_CHANGED", "path": p})
    return problems


def changed_paths(root: Path, base_ref: str | None, explicit: list[str]) -> list[str]:
    if explicit:
        if any(not inside_repo_path(x) for x in explicit):
            raise ValueError("invalid changed file path")
        return sorted(set(explicit))
    if not base_ref or not re.fullmatch(r"[A-Za-z0-9._/~-]+", base_ref) or base_ref.startswith("-"):
        raise ValueError("--base-ref is required for git diff, and must be a safe Git ref")
    run = subprocess.run(["git", "-C", str(root), "diff", "--name-only", "--diff-filter=ACMRT", "-z", base_ref, "HEAD"], capture_output=True, check=True)
    return sorted(set(p for p in run.stdout.decode("utf-8").split("\0") if p))


def check_changed(root: Path, evidence: list[dict], changes: list[str]) -> list[dict]:
    problems = []
    revised = [x for x in evidence if any(p.startswith(x["directory"] + "/") for p in changes)]
    for record in revised:
        defects = record["missing"] + record.get("invalid_fields", [])
        if record.get("error"):
            defects.append(record["error"])
        if defects:
            problems.append({"code": "INCOMPLETE_EVIDENCE", "path": record["directory"], "details": sorted(set(defects))})
    provider_sources = sorted({p.split("/")[3] for p in changes if p.startswith(PROVIDER_PREFIX) and len(p.split("/")) >= 5})
    other_sources = [p for p in changes if p in GENERIC_METHOD_PATHS or p.startswith("cloud/web/lib/") and (p.endswith("-protocol.mjs") or p.endswith("-source.mjs"))]
    for provider in provider_sources:
        prefix = PROVIDER_PREFIX + provider + "/"
        matching = [e for e in revised if any(c.startswith(prefix) for c in e["code_paths"])]
        if not matching:
            problems.append({"code": "MISSING_CHANGED_PROVIDER_DOSSIER", "provider": provider})
    for path in other_sources:
        if not any(path in e["code_paths"] for e in revised):
            problems.append({"code": "MISSING_CHANGED_CATALOG_DOSSIER", "path": path})
    if any(p.startswith(SHARED_PREFIX) and (p.endswith(".py") or p.endswith(".js") or p.endswith("requirements.txt")) for p in changes):
        if not any(p.startswith("analysis/platform/apk-tooling/") for p in changes):
            problems.append({"code": "TOOL_REGISTRY_UPDATE_REQUIRED"})
    return problems


def audit(root: Path, base_ref: str | None, explicit: list[str], enforce: bool) -> dict:
    tools = collect_tools(root)
    evidence = collect_evidence(root)
    problems = check_snapshot(root, tools)
    result = {
        "schema_version": 1,
        "scope": "F7-A0_STATIC_METADATA_ONLY",
        "tools": tools,
        "evidence": evidence,
        "snapshot_problems": problems,
        "summary": {
            "script_count": len(tools["tools"]),
            "pinned_requirement_count": sum(x["pinned"] for x in tools["requirements"]),
            "app_dossier_count": len(evidence),
            "structurally_complete_app_dossiers": sum(not x["missing"] and not x.get("error") and not x.get("invalid_fields") for x in evidence),
            "approved_for_unattended_execution": 0,
            "real_catalogs_validated_by_this_audit": 0,
        },
    }
    if enforce:
        changes = changed_paths(root, base_ref, explicit)
        result["changes"] = changes
        result["blocking_findings"] = check_changed(root, evidence, changes)
        # Existing backlog should not fail unrelated changes. Changes to shared tools
        # must update the baseline, which is checked here only if they occurred.
        if any(p.startswith(SHARED_PREFIX) and p.endswith((".py", ".js")) for p in changes):
            result["blocking_findings"].extend(problems)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--base-ref", help="trusted base ref for git diff against HEAD")
    parser.add_argument("--changed-file", action="append", default=[], help="for deterministic local tests")
    parser.add_argument("--enforce", action="store_true", help="reject changed methods without evidence")
    parser.add_argument("--output", type=Path, help="write sanitized JSON report")
    args = parser.parse_args(argv)
    try:
        report = audit(args.repo_root.resolve(), args.base_ref, args.changed_file, args.enforce)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"F7-A0 input error: {type(exc).__name__}", file=sys.stderr)
        return 2
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n", "utf-8")
    summary = report["summary"]
    print("F7-A0: tools={script_count} pinned-deps={pinned_requirement_count} app-dossiers={app_dossier_count} structurally-complete={structurally_complete_app_dossiers}".format(**summary))
    if args.enforce:
        for finding in report["blocking_findings"]:
            print(f"BLOCK: {finding['code']} {finding.get('path', finding.get('provider', ''))}")
        return 1 if report["blocking_findings"] else 0
    for finding in report["snapshot_problems"]:
        print(f"AUDIT: {finding['code']} {finding.get('path', '')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
