#!/usr/bin/env python3
"""F7-A0-P06: static Cloud/worker/decoder impact coverage and change gate.

Offline, standard-library-only. Never imports decoders, executes research tools,
reads APKs, connects to remote systems or approves unattended execution.
Legacy sources are inventoried without blocking unrelated changes. Any newly
changed method-bearing source requires a changed linked dossier; reverse static
imports expand the affected dossier set. Dynamic imports remain UNKNOWN.
"""
from __future__ import annotations

import argparse
import ast
from collections import defaultdict, deque
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))  # direct CLI invocation from scripts/ci/
from scripts.ci import check_method_evidence as base
SCAN_ROOTS = ("decoders/Python", "cloud/workers/python", "cloud/web/lib",
              "cloud/web/app/api", "scripts/apk_analysis")
EXTENSIONS = frozenset({".py", ".js", ".mjs", ".ts", ".tsx"})
IGNORE_PARTS = frozenset({"node_modules", "__pycache__", ".git", ".venv", "cache"})
MAX_SOURCE = 2_000_000
METHOD_NAMES = re.compile(
    r"(protocol|catalog|provider|gateway|format|source|decoder|bridge|"
    r"export|firebase|bundle|snapshot|chunk|decrypt|vpn|decode)", re.I
)
LITERAL_JS_IMPORT = re.compile(
    r"(?:\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*|^\s*import\s*)"
    r"['\"]([^'\"\n]+)['\"]", re.M
)
DYNAMIC_JS_IMPORT = re.compile(r"\b(?:import|require)\s*\(\s*[^'\"\s)]")
LITERAL_PY_FILE = re.compile(r"(?<![\w/])(?:decoders/Python/|scripts/apk_analysis/)"
                             r"[\w./-]+\.(?:py|js)\b")
LEGACY_REGISTRY = "analysis/platform/apk-tooling/legacy_provider_baseline.v1.json"
# P05 handoff before P06 began. Fixed in the validator as well as the registry;
# later PR edits cannot silently move the cutoff by editing JSON alone.
PINNED_CUTOVER_SHA = "4fddee8924e58a9d1e6476974e9b7a9adda3e495"


class CoverageError(ValueError):
    pass


def method_source(path: str) -> bool:
    p = Path(path)
    if p.suffix not in EXTENSIONS or "test" in p.parts or p.name.startswith("test_"):
        return False
    if path.startswith("decoders/Python/"):
        return p.suffix == ".py" and p.name != "__init__.py"
    if path.startswith("cloud/workers/python/"):
        return p.suffix in {".py", ".js"} and p.name != "__init__.py"
    if path.startswith("cloud/web/lib/"):
        return bool(METHOD_NAMES.search(p.stem))
    if path.startswith("cloud/web/app/api/"):
        return bool(METHOD_NAMES.search(path))
    if path.startswith("scripts/apk_analysis/"):
        return p.suffix in {".py", ".js"}
    return False


def sources(root: Path) -> dict[str, Path]:
    found = {}
    for folder in SCAN_ROOTS:
        base_dir = root / folder
        if not base_dir.is_dir() or base_dir.is_symlink():
            continue
        for p in base_dir.rglob("*"):
            if (p.is_symlink() or not p.is_file()
                    or any(part in IGNORE_PARTS for part in p.relative_to(root).parts)
                    or p.suffix not in EXTENSIONS or p.stat().st_size > MAX_SOURCE):
                continue
            found[p.relative_to(root).as_posix()] = p
    return dict(sorted(found.items()))


def resolve_module(spec: str, origin: str, available: set[str],
                   *, relative: bool = False, level: int = 0) -> set[str]:
    """Resolve literal Python imports and JS relative imports only."""
    candidates = []
    if relative:
        parents = Path(origin).parent.parts
        if level > len(parents):
            return set()
        prefix = parents[:len(parents) - max(0, level - 1)]
        candidates.append("/".join((*prefix, *spec.split("."))) if spec else "/".join(prefix))
    elif spec.startswith("."):
        candidate = Path(origin).parent / spec
        candidates.append(candidate.as_posix())
    elif spec.startswith(("decoders.", "cloud.", "scripts.")):
        candidates.append(spec.replace(".", "/"))
    for candidate in candidates:
        candidate = candidate.strip("/")
        for ext in (".py", ".js", ".mjs", ".ts", ".tsx"):
            path = candidate + ext
            if path in available:
                yield_path = path
                return {yield_path}
        for ext in (".py", ".js", ".mjs"):
            path = candidate + "/__init__" + ext
            if path in available:
                return {path}
    return set()


def dependencies(path: str, data: str, available: set[str]) -> tuple[set[str], list[str]]:
    dependencies_found: set[str] = set()
    signals: set[str] = set()
    if path.endswith(".py"):
        try:
            tree = ast.parse(data)
        except SyntaxError:
            return set(), ["PARSE_ERROR_UNRESOLVED"]
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    dependencies_found.update(resolve_module(alias.name, path, available))
            elif isinstance(node, ast.ImportFrom):
                prefix = node.module or ""
                dependencies_found.update(resolve_module(prefix, path, available,
                                                         relative=bool(node.level),
                                                         level=node.level))
                # "from ... import module" can reference a child module.
                for alias in node.names:
                    sub = ".".join(x for x in (prefix, alias.name) if x)
                    dependencies_found.update(resolve_module(sub, path, available,
                                                             relative=bool(node.level),
                                                             level=node.level))
            elif isinstance(node, ast.Call):
                name = node.func
                if ((isinstance(name, ast.Name) and name.id == "__import__")
                    or (isinstance(name, ast.Attribute) and name.attr == "import_module")):
                    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                        resolved = resolve_module(node.args[0].value, path, available)
                        dependencies_found.update(resolved)
                        if not resolved:
                            signals.add("DYNAMIC_LITERAL_UNRESOLVED")
                    else:
                        signals.add("DYNAMIC_IMPORT_UNKNOWN_TARGET")
        for item in LITERAL_PY_FILE.findall(data):
            if item in available:
                dependencies_found.add(item)
    else:
        for match in LITERAL_JS_IMPORT.finditer(data):
            spec = match.group(1)
            if not spec.startswith("."):
                continue
            origin = Path(path).parent
            p = (origin / spec).as_posix()
            # Resolve path components using PurePath normalisation without filesystem access.
            chunks = []
            for part in p.split("/"):
                if part == "..":
                    if chunks:
                        chunks.pop()
                elif part and part != ".":
                    chunks.append(part)
            prefix = "/".join(chunks)
            for name in (prefix, *(prefix + ext for ext in EXTENSIONS),
                         prefix + "/index.mjs", prefix + "/index.js"):
                if name in available:
                    dependencies_found.add(name)
                    break
        if DYNAMIC_JS_IMPORT.search(data):
            signals.add("DYNAMIC_IMPORT_UNKNOWN_TARGET")
    dependencies_found.discard(path)
    return dependencies_found, sorted(signals)


def inventory(root: Path) -> tuple[dict[str, dict], dict[str, set[str]]]:
    available = sources(root)
    names = set(available)
    items = {}
    reverse = defaultdict(set)
    for rel, filepath in available.items():
        raw = filepath.read_bytes()
        try:
            body = raw.decode("utf-8")
        except UnicodeError:
            body = ""
            unresolved = ["NON_UTF8_UNRESOLVED"]
            deps = set()
        else:
            deps, unresolved = dependencies(rel, body, names)
        for dep in deps:
            reverse[dep].add(rel)
        items[rel] = {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "method_candidate": method_source(rel),
            "direct_static_dependencies": sorted(deps),
            "uncertainty": unresolved,
        }
    return items, reverse


def affected(changes: list[str], reverse: dict[str, set[str]]) -> dict[str, list[str]]:
    origins = {path: [path] for path in changes}
    queue = deque(sorted(changes))
    while queue:
        changed = queue.popleft()
        for consumer in sorted(reverse.get(changed, ())):
            if consumer not in origins:
                origins[consumer] = origins[changed] + [consumer]
                queue.append(consumer)
    return dict(sorted(origins.items()))


def legacy_summary(root: Path) -> dict:
    path = root / LEGACY_REGISTRY
    if not path.is_file():
        return {"status": "MISSING_BASELINE", "provider_count": 0, "unreviewed": 0}
    obj = json.loads(path.read_text("utf-8"))
    names = obj.get("providers", [])
    if (obj.get("schema_version") != 1 or not isinstance(names, list)
        or any(not isinstance(x, dict) or not isinstance(x.get("folder"), str)
               or x.get("status") != "LEGACY_UNREVIEWED" for x in names)
        or len({x["folder"] for x in names}) != len(names)):
        raise CoverageError("Invalid legacy provider baseline")
    actual = {p.name for p in (root / "decoders/Python/apps").iterdir()
              if p.is_dir() and not p.is_symlink()} if (root / "decoders/Python/apps").is_dir() else set()
    registered = {x["folder"] for x in names}
    # Existing unmatched paths are visible as backlog; this is not approval.
    return {"status": "BASELINE_STATIC_UNREVIEWED", "provider_count": len(names),
            "unreviewed": len(names), "added_since_baseline": sorted(actual - registered),
            "removed_since_baseline": sorted(registered - actual),
            "baseline_commit": obj.get("source_commit")}



def post_cutover_changed_paths(root: Path, base_sha: str, head_sha: str,
                               cutoff_sha: str = PINNED_CUTOVER_SHA) -> tuple[list[str], list[str]]:
    """Return enforceable changes and historical PR changes, fail closed.

    Inspect the complete PR against its base, but enforce only paths with a
    net source change since the immutable P05->P06 cutover on this PR head.
    No old path gets a permanent exemption: its next edit is enforceable.
    The cutoff must be an ancestor of the actual PR head (not a merge ref).
    """
    if not all(re.fullmatch(r"[0-9a-f]{40}", s or "") for s in (base_sha, head_sha, cutoff_sha)):
        raise CoverageError("P06 requires exact 40-digit SHA refs")
    if cutoff_sha != PINNED_CUTOVER_SHA:
        raise CoverageError("P06 cutoff cannot be substituted")
    baseline = json.loads((root / LEGACY_REGISTRY).read_text("utf-8"))
    if baseline.get("source_commit") != PINNED_CUTOVER_SHA:
        raise CoverageError("P06 registry cutoff mismatches immutable SHA")
    if baseline.get("schema_version") != 1:
        raise CoverageError("P06 registry baseline schema mismatch")
    ancestor = subprocess.run(
        ["git", "-C", str(root), "merge-base", "--is-ancestor", cutoff_sha, head_sha],
        capture_output=True, check=False
    )
    if ancestor.returncode != 0:
        raise CoverageError("P06 cutoff not verified as ancestor of PR HEAD")
    all_changes = set(base.changed_paths(root, base_sha, []))
    delta = subprocess.run(
        ["git", "-C", str(root), "diff", "--name-only", "--diff-filter=ACMRT",
         "-z", cutoff_sha, head_sha], capture_output=True, check=True
    )
    after = set(filter(None, delta.stdout.decode("utf-8").split("\0")))
    enforce_changes = sorted(all_changes & after)
    historical = sorted(all_changes - after)
    return enforce_changes, historical


def audit(root: Path, changes: list[str] | None = None, *, enforce: bool = False) -> dict:
    root = root.resolve()
    records = base.collect_evidence(root)
    items, reverse = inventory(root)
    changes = sorted(set(changes or []))
    if any(not base.inside_repo_path(x) for x in changes):
        raise CoverageError("Invalid changed path")
    impact = affected([x for x in changes if x in items or method_source(x)], reverse)
    dossiers = {d["directory"]: d for d in records}
    matched = defaultdict(set)
    for dossier in records:
        for src in dossier["code_paths"]:
            matched[src].add(dossier["directory"])
    updated = {d for d in dossiers if any(x.startswith(d + "/") for x in changes)}
    changed_methods = [x for x in changes if method_source(x)]
    findings = []
    for p in changed_methods:
        linked = matched.get(p, set())
        if not linked or not linked.intersection(updated):
            findings.append({"code": "CHANGED_METHOD_WITHOUT_UPDATED_DOSSIER", "path": p,
                             "linked_dossiers": sorted(linked)})
    for consumer, chain in impact.items():
        if consumer in changed_methods or consumer not in items:
            continue
        if not items[consumer]["method_candidate"]:
            continue
        missing = sorted(matched.get(consumer, set()) - updated)
        if missing:
            for dossier in missing:
                findings.append({"code": "AFFECTED_DOSSIER_REVIEW_REQUIRED",
                                 "path": consumer, "dossier": dossier,
                                 "dependency_chain": chain})
    # Legacy backlog and unmapped consumers are reported, never silently APPROVED.
    unresolved_consumers = sorted(
        c for c in impact
        if c in items and items[c]["method_candidate"] and not matched.get(c)
    )
    report = {"schema_version": 1, "scope": "F7_A0_P06_STATIC_IMPACT_ONLY",
              "execution": "NO_TOOL_OR_APK_EXECUTION",
              "approval": "NONE_GRANTED",
              "summary": {"scanned_sources": len(items),
                          "method_candidates": sum(bool(x["method_candidate"]) for x in items.values()),
                          "changed_methods": len(changed_methods),
                          "affected_sources": len(impact),
                          "affected_dossiers": len({d for p in impact for d in matched.get(p, ())}),
                          "unresolved_affected_consumers": len(unresolved_consumers)},
              "legacy": legacy_summary(root),
              "source_inventory": [
                  {"path": path, "sha256": info["sha256"],
                   "method_candidate": info["method_candidate"],
                   "direct_static_dependencies": info["direct_static_dependencies"],
                   "uncertainty": info["uncertainty"],
                   "linked_dossiers": sorted(matched.get(path, ()))}
                  for path, info in sorted(items.items())
              ],
              "changed_paths": changes,
              "affected": [{"path": k, "via": chain, "sha256": items[k]["sha256"] if k in items else None,
                            "direct_dependencies": items[k]["direct_static_dependencies"] if k in items else [],
                            "uncertainty": items[k]["uncertainty"] if k in items else [],
                            "dossiers": sorted(matched.get(k, []))}
                           for k, chain in impact.items()],
              "unresolved_consumers": unresolved_consumers,
              "findings": findings}
    report["gate_status"] = "FAIL" if enforce and findings else (
        "PASS_WITH_UNRESOLVED" if unresolved_consumers else "PASS")
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo-root", type=Path, default=ROOT)
    ap.add_argument("--base-ref", help="PR base commit SHA")
    ap.add_argument("--pr-head-ref", help="exact PR head commit SHA for post-cutover diff")
    ap.add_argument("--legacy-cutover-ref", help="immutable P05/P06 cutover commit SHA")
    ap.add_argument("--changed-file", action="append", default=[])
    ap.add_argument("--enforce", action="store_true")
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    try:
        historical = []
        if args.enforce and args.legacy_cutover_ref:
            if args.changed_file or not args.pr_head_ref or not args.base_ref:
                raise CoverageError("Cutover gate requires PR base/head SHAs and no explicit fixtures")
            changes, historical = post_cutover_changed_paths(
                args.repo_root.resolve(), args.base_ref, args.pr_head_ref,
                args.legacy_cutover_ref
            )
        else:
            changes = (base.changed_paths(args.repo_root, args.base_ref, args.changed_file)
                       if args.enforce else [])
        report = audit(args.repo_root, changes, enforce=args.enforce)
        if args.enforce and args.legacy_cutover_ref:
            report["enforcement_cutover_sha"] = PINNED_CUTOVER_SHA
            report["pre_cutover_pr_paths_report_only"] = historical
            report["pre_cutover_pr_paths_unapproved"] = len(historical)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("P06 coverage input error: " + type(exc).__name__, file=sys.stderr)
        return 2
    s = report["summary"]
    print("P06: scanned={scanned_sources} method_candidates={method_candidates} "
          "changed={changed_methods} affected={affected_sources} "
          "dossiers={affected_dossiers} unknown={unresolved_affected_consumers} "
          "status=".format(**s) + report["gate_status"])
    for issue in report["findings"]:
        print("BLOCK: " + issue["code"] + " " + issue["path"])
    return 1 if args.enforce and report["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
