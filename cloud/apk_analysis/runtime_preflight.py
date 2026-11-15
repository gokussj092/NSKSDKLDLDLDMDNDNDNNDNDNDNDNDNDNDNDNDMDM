"""Offline F7-A0-P03 runtime preflight; no APKs read or tools executed."""
from __future__ import annotations

import argparse
import hashlib
from importlib import metadata
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
REQ = ROOT / "scripts/apk_analysis/requirements.txt"
JADX_VERSION = "1.5.6"
JADX_SHA256 = "fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b"
JADX = ROOT / "scripts/apk_analysis/cache" / ("jadx-" + JADX_VERSION + "-all.jar")


def check(allow_unprepared: bool = False) -> dict:
    installed = {}
    for line in REQ.read_text("utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)", line)
        if not match:
            raise ValueError("Unpinned analysis requirement")
        package, required = match.groups()
        try:
            actual = metadata.version(package)
        except metadata.PackageNotFoundError as exc:
            raise ValueError("Missing analysis dependency: " + package) from exc
        if actual != required:
            raise ValueError("Dependency drift: " + package)
        installed[package] = actual
    cmd = subprocess.run(["java", "-version"], capture_output=True, text=True, timeout=10, check=False)
    if cmd.returncode != 0:
        raise ValueError("JDK/JRE is missing")
    if JADX.exists():
        if JADX.is_symlink() or not JADX.is_file():
            raise ValueError("JADX cache path is not a regular file")
        if hashlib.sha256(JADX.read_bytes()).hexdigest() != JADX_SHA256:
            raise ValueError("JADX cached jar SHA-256 mismatch")
        jadx_status = "HASH_VERIFIED"
    else:
        if not allow_unprepared:
            raise ValueError("JADX resource not preloaded; use maintenance profile once")
        jadx_status = "NOT_PRELOADED"
    return {"direct_dependencies": len(installed), "java_available": True,
            "jadx_cache": jadx_status, "network_required_for_analysis": False}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--allow-unprepared", action="store_true")
    args = ap.parse_args()
    try:
        print(json.dumps(check(allow_unprepared=args.allow_unprepared), sort_keys=True))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print("APK runtime preflight failed: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
