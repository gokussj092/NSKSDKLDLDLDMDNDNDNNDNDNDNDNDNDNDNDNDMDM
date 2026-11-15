"""F7-A7 bounded offline JADX recovery for previously validated APK input.

No uploaded code is executed. All Java logs and generated sources remain
private temporary files; only bounded metadata leaves this process.
"""
from __future__ import annotations

import re
import time
from .qa_method_recipes import merge_recipe_reports
from pathlib import Path
import zipfile

MAX_DEX_ATTEMPTS = 4
MAX_DEX_BYTES = 40 * 1024 * 1024
MAX_RECOVERY_BYTES = 96 * 1024 * 1024
MAX_SITE_EXPORT = 48
ATTEMPT_TIMEOUT = 75
DEX_NAME = re.compile(r"classes(?:[2-9][0-9]*)?\.dex\Z")

ERROR_SIGNATURES = (
    ("JAVA_HEAP_EXHAUSTED", re.compile(rb"(OutOfMemoryError|Java heap space|GC overhead limit exceeded)", re.I)),
    ("CONTAINER_MEMORY_PRESSURE", re.compile(rb"(Cannot allocate memory|Killed process|memory allocation failed)", re.I)),
    ("DISK_EXHAUSTED", re.compile(rb"(No space left on device|Disk quota exceeded)", re.I)),
    ("DEX_PARSE_ERROR", re.compile(rb"(DexException|bad dex|invalid dex|DexParseException|invalid opcode)", re.I)),
    ("JAVA_ARGUMENT_ERROR", re.compile(rb"(Unrecognized option|Unknown option|Invalid option|Could not find or load main class)", re.I)),
    ("JAVA_ACCESS_ERROR", re.compile(rb"(Permission denied|AccessDeniedException)", re.I)),
)


def diagnose_termination(logfile: Path, termination: str) -> str:
    """Classify known failures from a small log tail without returning any text."""
    if termination == "EXIT_ZERO":
        return "NONE"
    if termination == "TIMEOUT":
        return "TIME_LIMIT_EXCEEDED"
    if termination == "START_FAILED":
        return "PROCESS_START_FAILED"
    try:
        with Path(logfile).open("rb") as stream:
            stream.seek(0, 2)
            stream.seek(max(0, stream.tell() - 65536))
            tail = stream.read(65536)
    except OSError:
        tail = b""
    for label, pattern in ERROR_SIGNATURES:
        if pattern.search(tail):
            return label
    return "NONE" if termination == "EXIT_ZERO" else "EXIT_NONZERO_UNCLASSIFIED"


def extract_dex_candidates(apk: Path, target: Path, *, max_attempts: int = MAX_DEX_ATTEMPTS) -> tuple[list[Path], dict]:
    """Extract at most four bounded DEX files, with no unsafe archive paths."""
    candidates: list[Path] = []
    meta = {"dexDiscovered": 0, "dexSelected": 0, "dexSkipped": 0,
            "dexTooLarge": 0, "dexExtractedBytes": 0, "extractionStatus": "OK"}
    try:
        with zipfile.ZipFile(apk) as archive:
            entries = [info for info in archive.infolist() if DEX_NAME.fullmatch(info.filename)]
            entries.sort(key=lambda info: (0 if info.filename == "classes.dex" else
                         int(info.filename[7:-4]), info.filename))
            meta["dexDiscovered"] = len(entries)
            for entry in entries:
                if len(candidates) >= max_attempts:
                    meta["dexSkipped"] += 1
                    continue
                if (entry.file_size <= 0 or entry.file_size > MAX_DEX_BYTES or
                    meta["dexExtractedBytes"] + entry.file_size > MAX_RECOVERY_BYTES):
                    meta["dexTooLarge"] += 1
                    continue
                output = target / ("recovery-" + str(len(candidates)) + ".dex")
                copied = 0
                with archive.open(entry) as src, output.open("xb") as dst:
                    while chunk := src.read(256 * 1024):
                        copied += len(chunk)
                        if copied > entry.file_size or copied > MAX_DEX_BYTES:
                            raise ValueError("DEX_BOUNDS")
                        dst.write(chunk)
                if copied != entry.file_size:
                    raise ValueError("DEX_TRUNCATED")
                meta["dexExtractedBytes"] += copied
                candidates.append(output)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
        meta["extractionStatus"] = "EXTRACTION_FAILED"
    meta["dexSelected"] = len(candidates)
    return candidates, meta


def recover_jadx(apk: Path, scratch: Path, jar: Path, env: dict,
                 run_jadx, scan_sources, *, profile: dict | None = None,
                 deadline: float | None = None) -> dict:
    """Sequential retries. Never asserts whole-APK completion."""
    dex_inputs, coverage = extract_dex_candidates(apk, scratch,
        max_attempts=profile["recoveryDex"] if profile else MAX_DEX_ATTEMPTS)
    recipe_reports = []
    attempts = []
    reference_sites = []
    references_seen = set()
    counts = {}
    inspected = 0
    bytes_inspected = 0
    sites_observed = 0
    recovered = 0
    for index, candidate in enumerate(dex_inputs):
        # Multi-megabyte DEX files on 1 CPU routinely time out in simple mode.
        # Prefer the already proven fallback, keeping both modes for small DEX.
        large = candidate.stat().st_size >= 6 * 1024 * 1024
        modes = ("auto", "fallback") if profile else (("fallback",) if large else ("simple", "fallback"))
        for mode in modes:
            seconds = profile["recoverySeconds"] if profile else (120 if large else ATTEMPT_TIMEOUT)
            if deadline is not None:
                seconds = min(seconds, max(0, int(deadline - time.monotonic())))
            if seconds < 1:
                coverage["recoveryBudgetExhausted"] = True
                break
            output = scratch / ("recovery-output-" + str(index) + "-" + mode)
            output.mkdir(mode=0o700)
            log = scratch / ("recovery-" + str(index) + "-" + mode + ".log")
            command = ["java", "-Xmx"+profile["heap"] if profile else "-Xmx512m",
                       "-XX:ActiveProcessorCount="+str(profile["threads"]) if profile else "-XX:ActiveProcessorCount=1",
                       "-cp", str(jar), "jadx.cli.JadxCLI", "--no-res",
                       "--decompilation-mode", mode, "-j", str(profile["threads"]) if profile else "1",
                       "-d", str(output), str(candidate)]
            termination = run_jadx(command, cwd=scratch,
                                   timeout=seconds,
                                   env=env, logfile=log)
            summary = scan_sources(output)
            recipe_reports.append(summary.get("methodRecipes", {}))
            generated = int(summary.get("sourceFilesInspected", 0))
            # A zero exit without generated sources is not useful recovery.
            successful = termination == "EXIT_ZERO" and generated > 0
            attempts.append({
                "dexIndex": index + 1, "mode": mode, "terminationReason": termination,
                "failureCategory": diagnose_termination(log, termination),
                "sourceFilesInspected": generated,
                "completed": termination == "EXIT_ZERO", "usableSource": generated > 0,
                "dexFirstLargeMode": large,
            })
            inspected += generated
            bytes_inspected += int(summary.get("sourceBytesInspected", 0))
            sites_observed += int(summary.get("candidateCallSitesObserved",
                                               len(summary.get("candidateCallSites", []))))
            for label, value in summary.get("cryptoReferenceCounts", {}).items():
                if label in ("JCA_CIPHER", "JCA_KEY_SPEC", "JCA_GCM", "JCA_MAC",
                             "JCA_DIGEST", "JCA_PBKDF", "JNI_LOADER", "ANDROID_BASE64"):
                    counts[label] = counts.get(label, 0) + int(value)
            for site in summary.get("candidateCallSites", []):
                if not isinstance(site, dict):
                    continue
                key = (site.get("class"), site.get("method"), site.get("indicator"))
                if key not in references_seen and len(reference_sites) < MAX_SITE_EXPORT:
                    references_seen.add(key)
                    reference_sites.append(site)
            if successful:
                recovered += 1
                break
    return {
        **coverage, "attempts": attempts, "dexRecovered": recovered,
        "methodRecipes": merge_recipe_reports(recipe_reports),
        "sourceFilesInspected": inspected, "sourceBytesInspected": bytes_inspected,
        "candidateCallSites": reference_sites,
        "candidateCallSitesObserved": sites_observed,
        "candidateCallSitesTruncated": sites_observed > len(reference_sites),
        "cryptoReferenceCounts": counts,
        "referencesMayOverlapPrimary": True,
        "methodValidated": False,
        "status": ("RECOVERED_PARTIAL" if inspected else "NO_RECOVERABLE_SOURCE"),
    }
