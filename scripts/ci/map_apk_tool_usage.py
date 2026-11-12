#!/usr/bin/env python3
"""F7-A0-P02: read-only map of existing APK research tools and references.

Parses source text only. Never imports tool modules, executes scripts,
launches programs, connects to networks or opens APK samples.
Findings are static signals, not confirmed behavior or execution approvals.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = "analysis/platform/apk-tooling/tool_sources.v1.json"
SCAN_DIRS = ("analysis", "docs", "tests", "decoders/Python/apps")
TEXT_SUFFIXES = {".py", ".js", ".mjs", ".md", ".txt", ".json", ".sh"}
SKIP = {".git", "node_modules", "cache", "work", "__pycache__", ".venv"}
FILE_LIMIT = 1_000_000
REF_LIMIT = 100
THIRD_PARTY = {"androguard", "elftools", "capstone", "unicorn", "Crypto",
               "PIL", "cairosvg", "frida", "frida_tools", "loguru", "requests",
               "httpx", "cryptography", "nacl", "lxml", "lz4", "bs4"}


class UsageMapError(ValueError):
    pass


def git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def _call_name(expr: ast.expr) -> str:
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        return _call_name(expr.value) + "." + expr.attr
    return ""


def python_signals(text: str, siblings: set[str]) -> dict:
    result = {"parse_status": "OK", "cli_flags": [], "cli_positionals": [],
              "external_imports": [], "sibling_imports": [],
              "static_signals": [], "abi_literal_hints": []}
    try:
        tree = ast.parse(text)
    except SyntaxError:
        result["parse_status"] = "SYNTAX_ERROR_NOT_EXECUTED"
        return result
    imports = set()
    calls = set()
    flags = set()
    args = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(x.name.split(".")[0] for x in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name:
                calls.add(name)
            if name.endswith(".add_argument") and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    (flags if arg.value.startswith("-") else args).add(arg.value)
    signals = set()
    if imports.intersection({"requests", "httpx", "socket", "aiohttp"}) or calls.intersection({
        "urlopen", "urllib.request.urlopen", "urlretrieve", "build_opener",
        "urllib.request.build_opener", "requests.get", "requests.post",
        "requests.request", "httpx.get", "httpx.post",
    }):
        signals.add("NETWORK_API")
    if calls.intersection({
        "subprocess.run", "subprocess.Popen", "subprocess.call",
        "subprocess.check_output", "subprocess.check_call", "os.system",
        "os.popen", "Popen", "check_output",
    }):
        signals.add("PROCESS_LAUNCH")
    if "frida" in imports or "frida." in text.lower():
        signals.add("RUNTIME_INSTRUMENTATION")
    if imports.intersection({"elftools", "capstone", "unicorn"}):
        signals.add("NATIVE_BINARY_INSPECTION")
    if "unicorn" in imports:
        signals.add("EMULATION_API")
    if '"adb"' in text or "'adb'" in text:
        signals.add("ANDROID_DEVICE_API")
    if any(n.endswith((".write_bytes", ".write_text", ".mkdir", ".unlink",
                        ".rename", ".replace", ".chmod", ".writestr", ".extractall"))
           for n in calls) or calls.intersection({"os.remove", "os.unlink", "os.makedirs"}):
        signals.add("FILESYSTEM_WRITE_API")
    if imports.intersection({"zipfile", "tarfile", "androguard"}):
        signals.add("ARCHIVE_PARSING_API")
    if imports.intersection({"Crypto", "cryptography", "nacl"}):
        signals.add("CRYPTO_LIBRARY_IMPORT")
    if imports.intersection({"PIL", "cairosvg"}) or "vectordrawable" in text.lower():
        signals.add("IMAGE_PROCESSING_API")
    if calls.intersection({"hashlib.sha256", "hashlib.sha1", "hashlib.sha512"}):
        signals.add("HASHING_API")
    hints = []
    if re.search(r"arm64|aarch64|arm64-v8a", text, re.I):
        hints.append("ARM64_MENTION")
    if re.search(r"x86_64|amd64", text, re.I):
        hints.append("X86_64_MENTION")
    result.update({
        "cli_flags": sorted(flags), "cli_positionals": sorted(args),
        "external_imports": sorted(imports & THIRD_PARTY),
        "sibling_imports": sorted(imports & siblings),
        "static_signals": sorted(signals), "abi_literal_hints": hints,
    })
    return result


def js_signals(text: str) -> dict:
    signals = set()
    if re.search(r"\b(?:Java\.use|Interceptor\.attach|Module\.findExportByName)\b", text):
        signals.add("RUNTIME_INSTRUMENTATION")
    if re.search(r"\b(?:fetch\s*\(|XMLHttpRequest|WebSocket)\b", text):
        signals.add("NETWORK_API")
    if "MessageDigest" in text or "createHash" in text:
        signals.add("HASHING_API")
    return {"parse_status": "TEXT_INSPECTED_NOT_EXECUTED", "cli_flags": [],
            "cli_positionals": [], "external_imports": [], "sibling_imports": [],
            "static_signals": sorted(signals),
            "abi_literal_hints": ["ARM64_MENTION"] if re.search(r"arm64|aarch64", text, re.I) else []}


def reference_files(root: Path):
    for prefix in SCAN_DIRS:
        directory = root / prefix
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*")):
            if path.is_symlink() or not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            if any(part in SKIP for part in path.relative_to(root).parts):
                continue
            if path.stat().st_size <= FILE_LIMIT:
                yield path
    for name in ("scripts/apk_analysis/README.md", "scripts/apk_analysis/RESTORE.md"):
        path = root / name
        if path.is_file() and not path.is_symlink() and path.stat().st_size <= FILE_LIMIT:
            yield path


def reference_kind(path: str) -> tuple[str, str | None]:
    parts = path.split("/")
    if len(parts) >= 4 and parts[0] == "analysis" and re.fullmatch(r"\d+", parts[2]):
        return "APP_BUILD_DOSSIER_REFERENCE", parts[1] + "/" + parts[2]
    if path.startswith("tests/") or "/tests/" in path:
        return "TEST_SOURCE_REFERENCE", None
    if path.startswith("decoders/"):
        return "DECODER_SOURCE_OR_DOCUMENT_REFERENCE", None
    return "DOCUMENTATION_OR_SOURCE_REFERENCE", None


def find_references(root: Path, tools: list[dict]) -> dict[str, list[dict]]:
    filenames = {Path(t["path"]).name: t["path"] for t in tools}
    modules = {Path(name).stem: path for name, path in filenames.items() if name.endswith(".py")}
    filename_pattern = re.compile(
        r"(?<![A-Za-z0-9_.-])(" +
        "|".join(re.escape(name) for name in sorted(filenames, key=len, reverse=True)) +
        r")(?![A-Za-z0-9_.-])"
    )
    module_pattern = re.compile(
        r"(?<![A-Za-z0-9_])(" +
        "|".join(re.escape(name) for name in sorted(modules, key=len, reverse=True)) +
        r")(?![A-Za-z0-9_])"
    )
    matches = {tool["path"]: set() for tool in tools}
    for path in reference_files(root):
        rel = path.relative_to(root).as_posix()
        # Registry files are their own source inventory, not evidence of a
        # real consumer. Without this exclusion every tool appears in use.
        if rel.startswith("analysis/platform/") or rel.startswith("analysis/_intake/"):
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeError:
            continue
        for number, line in enumerate(content.splitlines(), 1):
            for m in filename_pattern.finditer(line):
                kind, app = reference_kind(rel)
                matches[filenames[m.group(1)]].add((rel, number, kind, app or "", "EXPLICIT_FILENAME"))
            if path.suffix == ".py" and re.match(r"^\s*(?:from|import)\s+", line):
                for m in module_pattern.finditer(line):
                    kind, app = reference_kind(rel)
                    matches[modules[m.group(1)]].add((rel, number, kind, app or "", "IMPORT_TOKEN"))
    return {
        key: [{"source": r, "line": n, "kind": k, "app_build": a or None, "signal": signal}
              for r, n, k, a, signal in sorted(entries)]
        for key, entries in matches.items()
    }


def audit(root: Path = ROOT) -> dict:
    root = root.resolve()
    inventory = json.loads((root / SNAPSHOT).read_text(encoding="utf-8"))
    sources = inventory.get("sources")
    if inventory.get("schema_version") != 1 or not isinstance(sources, list) or not sources:
        raise UsageMapError("Invalid shared tool inventory")
    if len({x["path"] for x in sources}) != len(sources):
        raise UsageMapError("Duplicate registered tool")
    expected = {x["path"] for x in sources}
    folder = root / "scripts/apk_analysis"
    actual = {p.relative_to(root).as_posix() for p in folder.iterdir()
              if p.is_file() and p.suffix in (".py", ".js")} if folder.is_dir() else set()
    if expected != actual:
        raise UsageMapError("Shared tool paths do not match inventory")
    siblings = {Path(path).stem for path in expected if path.endswith(".py")}
    tools = []
    for info in sorted(sources, key=lambda x: x["path"]):
        name = info["path"]
        if not name.startswith("scripts/apk_analysis/") or Path(name).name != name.split("/")[-1]:
            raise UsageMapError("Invalid inventory tool path")
        data = (root / name).read_bytes()
        if git_blob(data) != info["git_blob_sha1"] or len(data) != info["size"]:
            raise UsageMapError("Shared tool changed: " + name)
        try:
            content = data.decode("utf-8")
        except UnicodeError:
            raise UsageMapError("Non-UTF8 tool source: " + name)
        static = python_signals(content, siblings - {Path(name).stem}) if name.endswith(".py") else js_signals(content)
        tools.append({
            "path": name, "size_bytes": len(data),
            "git_blob_sha1": info["git_blob_sha1"],
            "source_sha256": hashlib.sha256(data).hexdigest(),
            "source_type": "PYTHON" if name.endswith(".py") else "JAVASCRIPT",
            "source_assessment": static,
            "unattended_execution": "NOT_APPROVED",
        })
    refs = find_references(root, tools)
    for tool in tools:
        items = refs[tool["path"]]
        tool["documented_app_build_references"] = sorted({x["app_build"] for x in items if x["app_build"]})
        tool["test_source_references"] = sorted({
            x["source"] for x in items
            if x["kind"] == "TEST_SOURCE_REFERENCE" or "/tests/" in x["source"]
        })
        tool["reference_count"] = len(items)
        tool["references"] = items[:REF_LIMIT]
        tool["references_truncated"] = len(items) > REF_LIMIT
        tool["consumer_confidence"] = "STATIC_REFERENCE_ONLY" if items else "NO_EXPLICIT_REFERENCE_FOUND"
    summary = {
        "tool_count": len(tools),
        "unchanged_source_count": len(tools),
        "python_count": sum(x["source_type"] == "PYTHON" for x in tools),
        "javascript_count": sum(x["source_type"] == "JAVASCRIPT" for x in tools),
        "referenced_tool_count": sum(x["reference_count"] > 0 for x in tools),
        "app_dossier_linked_tool_count": sum(bool(x["documented_app_build_references"]) for x in tools),
        "test_source_linked_tool_count": sum(bool(x["test_source_references"]) for x in tools),
        "no_reference_tool_count": sum(x["reference_count"] == 0 for x in tools),
        "parse_errors": sum(x["source_assessment"]["parse_status"] == "SYNTAX_ERROR_NOT_EXECUTED" for x in tools),
        "approved_for_unattended_execution": 0,
    }
    return {
        "schema_version": 1, "scope": "F7_A0_P02_STATIC_TOOL_REFERENCE_INVENTORY",
        "execution": "NO_TOOL_EXECUTED", "network": "NO_REQUESTS",
        "research_baseline_commit": inventory.get("source_commit"),
        "definitions": {
            "cli_flags": "Literal argparse option labels, not approved arguments",
            "abi_literal_hints": "Source mentions only, not tested compatibility",
            "static_signals": "API presence only, not evidence of execution",
            "documented_app_build_references": "Explicit references, not full dependency proof",
            "test_source_references": "Textual test references, not test execution proof",
        },
        "summary": summary, "tools": tools,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = audit(args.repo_root)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", "utf-8")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("F7-A0-P02 FAIL: " + str(exc), file=sys.stderr)
        return 1
    s = report["summary"]
    print(
        "F7-A0-P02: tools={tool_count} unchanged={unchanged_source_count} "
        "python={python_count} js={javascript_count} referenced={referenced_tool_count} "
        "app-dossiers={app_dossier_linked_tool_count} tests={test_source_linked_tool_count} "
        "unmapped={no_reference_tool_count} parse-errors={parse_errors} "
        "approved={approved_for_unattended_execution}".format(**s)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
