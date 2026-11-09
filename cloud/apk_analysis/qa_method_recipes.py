"""Bounded static method recipes from real JADX output, never executable recipes.

Only allowlisted algorithms, API roles, method hashes and source coordinates
are exported. Keys, passwords, URLs, code, literals and logs stay private.
A candidate always needs a separate oracle; references are not a decryptor.
"""
from __future__ import annotations
from collections import defaultdict
import hashlib
import os
from pathlib import Path
import re
from .qa_jadx_refs import _is_framework, METHOD, IGNORE_METHOD

MAX_FILES = 40_000
MAX_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 256 * 1024
MAX_METHODS = 64
MAX_EDGES = 96
ALGORITHMS = {
    "AES", "AES/GCM/NoPadding", "AES/CBC/PKCS5Padding",
    "AES/CBC/PKCS7Padding", "AES/ECB/PKCS5Padding", "AES/CTR/NoPadding",
    "DES/CBC/PKCS5Padding", "DES/ECB/PKCS5Padding",
    "DESede/CBC/PKCS5Padding", "ChaCha20", "ChaCha20-Poly1305",
    "RSA/ECB/PKCS1Padding", "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
    "PBKDF2WithHmacSHA1", "PBKDF2WithHmacSHA256", "PBKDF2WithHmacSHA512",
    "HmacSHA1", "HmacSHA256", "HmacSHA512", "SHA-1", "SHA-256", "SHA-512",
}
APIS = (
    ("CIPHER_FACTORY", re.compile(r"\bCipher\s*\.\s*getInstance\s*\(")),
    ("CIPHER_INIT", re.compile(r"\b[A-Za-z_$][\w$]*\s*\.\s*init\s*\(")),
    ("CIPHER_FINAL", re.compile(r"\b[A-Za-z_$][\w$]*\s*\.\s*doFinal\s*\(")),
    ("KEY_SPEC", re.compile(r"\bSecretKeySpec\s*\(")),
    ("IV_SPEC", re.compile(r"\bIvParameterSpec\s*\(")),
    ("GCM_SPEC", re.compile(r"\bGCMParameterSpec\s*\(")),
    ("PBKDF_SPEC", re.compile(r"\bPBEKeySpec\s*\(")),
    ("KDF_FACTORY", re.compile(r"\bSecretKeyFactory\s*\.\s*getInstance\s*\(")),
    ("MAC_FACTORY", re.compile(r"\bMac\s*\.\s*getInstance\s*\(")),
    ("DIGEST_FACTORY", re.compile(r"\bMessageDigest\s*\.\s*getInstance\s*\(")),
    ("BASE64_DECODE", re.compile(r"\bBase64\s*\.\s*decode\s*\(|\bBase64\s*\.\s*getDecoder\s*\(\s*\)\s*\.\s*decode\s*\(")),
    ("BASE64_ENCODE", re.compile(r"\bBase64\s*\.\s*encodeToString\s*\(|\bBase64\s*\.\s*getEncoder\s*\(")),
    ("GZIP_INPUT", re.compile(r"\bGZIPInputStream\s*\(")),
    ("JNI_LOADER", re.compile(r"\bSystem\s*\.\s*loadLibrary\s*\(")),
    ("UPDATER_CONNECTION", re.compile(r"\b[A-Za-z_$][\w$]*\s*\.\s*openConnection\s*\(")),
)
SAFE_CLASS = re.compile(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*){0,30}\Z")

def mask_java(source: str) -> tuple[str, str]:
    """Preserve offsets/newlines, suppress comments and string lookalike code."""
    code = list(source)
    literals = list(source)
    at = 0
    while at < len(source):
        start = at
        if source.startswith("//", at):
            end = source.find("\n", at)
            at = len(source) if end < 0 else end
            for i in range(start, at):
                code[i] = literals[i] = " "
        elif source.startswith("/*", at):
            end = source.find("*/", at + 2)
            at = len(source) if end < 0 else end + 2
            for i in range(start, at):
                if source[i] != "\n":
                    code[i] = literals[i] = " "
        elif source[at] in "\"'":
            quote = source[at]
            at += 1
            while at < len(source):
                if source[at] == "\\":
                    at = min(len(source), at + 2)
                elif source[at] == quote:
                    at += 1
                    break
                else:
                    at += 1
            for i in range(start, at):
                if source[i] != "\n":
                    code[i] = " "
        else:
            at += 1
    return "".join(code), "".join(literals)

def _ranges(code: str) -> list[tuple]:
    pairs = {}
    stack = []
    for i, c in enumerate(code):
        if c == "{":
            stack.append(i)
        elif c == "}" and stack:
            pairs[stack.pop()] = i + 1
    out = []
    for match in list(METHOD.finditer(code))[:1024]:
        name = match.group("name")
        if name in IGNORE_METHOD:
            continue
        # A method body starts after its balanced argument list, not a declaration.
        at = match.end()
        depth = 1
        while at < len(code) and depth:
            depth += (code[at] == "(") - (code[at] == ")")
            at += 1
        end = min(len(code), at + 512)
        brace = code.find("{", at, end)
        semi = code.find(";", at, end)
        if brace < 0 or (0 <= semi < brace) or brace not in pairs:
            continue
        begin = match.start() + len(match.group()) - len(match.group().lstrip())
        out.append((begin, brace, pairs[brace], name))
    return out

def inspect_source(source: str, class_name: str) -> tuple[list[dict], list[dict]]:
    if not SAFE_CLASS.fullmatch(class_name) or len(class_name) > 190:
        return [], []
    code, literals = mask_java(source)
    methods = _ranges(code)
    records = {}
    spans = {}
    local_names = defaultdict(list)
    for begin, body, end, name in methods:
        method_hash = hashlib.sha256(source[begin:end].encode()).hexdigest()
        identity = hashlib.sha256((class_name + "#" + name + ":" + method_hash).encode()).hexdigest()[:20]
        spans[identity] = (begin, body, end, name)
        local_names[name].append(identity)
        observations = []
        algorithms = set()
        params = {}
        for label, pattern in APIS:
            for match in list(pattern.finditer(code, body, end))[:12]:
                observations.append({"role": label, "line": source.count("\n", 0, match.start()) + 1})
                if label.endswith("FACTORY"):
                    literal = re.match(r'\s*"([^"\\]{1,80})"', literals[match.end():match.end()+100])
                    if literal and literal.group(1) in ALGORITHMS:
                        algorithms.add(literal.group(1))
                if label == "GCM_SPEC":
                    number = re.match(r"\s*(96|104|112|120|128)\s*,", code[match.end():match.end()+32])
                    if number:
                        params["gcmTagBits"] = int(number.group(1))
                if label == "PBKDF_SPEC":
                    # Only simple numeric operands are asserted. Dynamic values stay unresolved.
                    numbers = re.match(r"[^,]{1,120},[^,]{1,120},\s*([0-9]{1,9})\s*,\s*(128|192|256|512)\s*\)",
                                       code[match.end():min(end, match.end()+300)])
                    if numbers:
                        params["pbkdfIterations"] = int(numbers.group(1))
                        params["derivedKeyBits"] = int(numbers.group(2))
        roles = {item["role"] for item in observations}
        # Generic object.init/doFinal alone do not establish a cryptographic method.
        if not roles.intersection({"CIPHER_FACTORY", "KEY_SPEC", "GCM_SPEC", "PBKDF_SPEC",
                                  "KDF_FACTORY", "MAC_FACTORY", "DIGEST_FACTORY",
                                  "JNI_LOADER", "UPDATER_CONNECTION"}):
            observations = []
        direction = "UNRESOLVED"
        body_text = code[body:end]
        if "Cipher.DECRYPT_MODE" in body_text:
            direction = "DECRYPT"
        elif "Cipher.ENCRYPT_MODE" in body_text:
            direction = "ENCRYPT"
        records[identity] = {
            "id": identity, "class": class_name, "method": name,
            "firstLine": source.count("\n", 0, begin) + 1,
            "lastLine": source.count("\n", 0, end) + 1,
            "sourceMethodSha256": method_hash,
            "observations": sorted(observations, key=lambda x: (x["line"], x["role"]))[:24],
            "algorithms": sorted(algorithms), "parameters": params,
            "directionObserved": direction, "status": "CANDIDATE_REQUIRES_ORACLE",
            "methodValidated": False, "keyMaterialExported": False,
        }
    edges = []
    simple_class = class_name.rsplit(".", 1)[-1]
    # One bounded lexical pass per body; do not compile N*N method regexes.
    call_pattern = re.compile(r"(?<![\w.$])(?:(?:this|" + re.escape(simple_class)
                              + r")\s*\.\s*)?(?P<name>[A-Za-z_$][\w$]*)\s*\(")
    for identity, item in records.items():
        span = spans[identity]
        for call in call_pattern.finditer(code, span[1], span[2]):
            for target in local_names.get(call.group("name"), []):
                if target != identity and len(edges) < MAX_EDGES:
                    edges.append({"caller": identity, "callee": target,
                                  "evidence": "SAME_CLASS_CALL_REFERENCE",
                                  "overloadResolution": "UNRESOLVED", "methodValidated": False})
    selected = {key for key, value in records.items() if value["observations"]}
    for _ in range(4):
        selected.update(e["caller"] for e in edges if e["callee"] in selected)
    return [records[key] for key in records if key in selected], [
        edge for edge in edges if edge["caller"] in selected and edge["callee"] in selected]

def scan_method_recipes(output: Path) -> dict:
    output = Path(output)
    root = output.resolve()
    found = []
    edges = []
    seen = set()
    total = 0
    files = 0
    observed = 0
    skipped = 0
    complete = True
    for current, dirs, names in os.walk(output, followlinks=False):
        parent = Path(current)
        dirs[:] = sorted(d for d in dirs if not (parent/d).is_symlink())
        if _is_framework(parent.relative_to(output)):
            dirs[:] = []
            continue
        for name in sorted(names):
            if not name.endswith(".java"):
                continue
            files += 1
            if files > MAX_FILES or total >= MAX_BYTES:
                complete = False
                break
            path = parent/name
            try:
                if path.is_symlink() or not path.resolve().is_relative_to(root):
                    skipped += 1
                    continue
                size = path.stat().st_size
                if size > MAX_FILE_BYTES or total + size > MAX_BYTES:
                    skipped += 1
                    continue
                total += size
                source = path.read_text("utf-8", "replace")
            except (OSError, ValueError):
                skipped += 1
                continue
            relative = path.relative_to(output).with_suffix("").parts
            while relative and relative[0] in ("sources", "src"):
                relative = relative[1:]
            records, calls = inspect_source(source, ".".join(relative))
            observed += len(records)
            for item in records:
                key = (item["class"], item["method"], item["sourceMethodSha256"])
                if key not in seen and len(found) < MAX_METHODS:
                    seen.add(key)
                    found.append(item)
            selected_ids = {item["id"] for item in found}
            edges.extend(edge for edge in calls if edge["caller"] in selected_ids
                         and edge["callee"] in selected_ids and len(edges) < MAX_EDGES)
        if not complete:
            break
    ids = {item["id"] for item in found}
    calls = []
    seen_calls = set()
    for edge in edges:
        key = (edge["caller"], edge["callee"])
        if key[0] in ids and key[1] in ids and key not in seen_calls and len(calls) < MAX_EDGES:
            seen_calls.add(key)
            calls.append(edge)
    return {"schemaVersion": 1, "status": "STATIC_METHOD_CANDIDATES",
            "methods": found, "sameClassCalls": calls,
            "methodsObserved": observed, "methodsTruncated": observed > len(found),
            "sourceFilesInspected": min(files, MAX_FILES), "sourceBytesInspected": total,
            "skippedLargeOrUnsafe": skipped, "sourceScanBudgetComplete": complete,
            "methodValidated": False, "codeExecuted": False,
            "rawSourceExported": False, "keyMaterialExported": False}


def merge_recipe_reports(reports: list[dict]) -> dict:
    methods = []
    edges = []
    seen = set()
    calls_seen = set()
    observed = 0
    for report in reports:
        if not isinstance(report, dict):
            continue
        observed += int(report.get("methodsObserved", 0))
        for method in report.get("methods", [])[:MAX_METHODS]:
            key = (method.get("class"), method.get("method"), method.get("sourceMethodSha256"))
            if key not in seen:
                seen.add(key)
                if len(methods) < MAX_METHODS:
                    methods.append(method)
        for edge in report.get("sameClassCalls", [])[:MAX_EDGES]:
            key = (edge.get("caller"), edge.get("callee"))
            if key not in calls_seen and len(edges) < MAX_EDGES:
                calls_seen.add(key)
                edges.append(edge)
    ids = {item["id"] for item in methods}
    return {"schemaVersion": 1, "status": "STATIC_METHOD_CANDIDATES",
            "methods": methods,
            "sameClassCalls": [e for e in edges if e["caller"] in ids and e["callee"] in ids],
            "methodsObserved": observed, "methodsTruncated": observed > len(methods) or len(seen) > len(methods),
            "observationsMayOverlapRetries": len(reports) > 1,
            "methodValidated": False, "codeExecuted": False,
            "rawSourceExported": False, "keyMaterialExported": False}
