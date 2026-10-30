#!/usr/bin/env python3
"""Reject Cloud release binaries with missing or mismatched local signer pins.

The trusted signer values are public certificate fingerprints, not credentials.
Use generated RELEASE BuildConfig rather than source defaults: the original
v1.1.24 signed APK could be validly signed yet exit on MainActivity.onCreate.
"""
import os
import re
import sys
from pathlib import Path

APK_CONFIG = Path("android/app/build/generated/source/buildConfig")
PACKAGE_PATH = "/release/com/ghostdeveloper/spdecode/BuildConfig.java"
KEYS = ("TRUSTED_SIGNER_SHA256", "PLAY_APP_SIGNER_SHA256")
ENV_NAMES = ("SPDECODE_TRUSTED_SIGNER_SHA256", "SPDECODE_PLAY_APP_SIGNER_SHA256")

def validate(source: str, environment: dict[str, str]) -> None:
    for field, name in zip(KEYS, ENV_NAMES):
        expected = environment.get(name, "").strip().lower()
        if not re.fullmatch(r"[a-f0-9]{64}", expected):
            raise ValueError(f"{name} must contain a 64-hex SHA-256")
        matches = re.findall(r"\b" + re.escape(field) + r'\s*=\s*"([^"]*)"', source)
        if matches != [expected]:
            raise ValueError(f"Signed release BuildConfig has missing/mismatched {field}")

def main() -> int:
    matched = [
        p for p in APK_CONFIG.rglob("BuildConfig.java")
        if p.as_posix().endswith(PACKAGE_PATH)
    ] if APK_CONFIG.exists() else []
    if len(matched) != 1:
        print("ERROR: Exactly one signed release BuildConfig.java is required", file=sys.stderr)
        return 1
    try:
        validate(matched[0].read_text(encoding="utf-8"), os.environ)
    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("PASS: Signed release contains both trusted certificate pins")
    return 0

if __name__ == "__main__":
    sys.exit(main())
