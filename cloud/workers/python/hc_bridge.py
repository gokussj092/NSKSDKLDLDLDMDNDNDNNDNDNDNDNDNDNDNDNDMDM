#!/usr/bin/env python3
"""Credential-aware HCCFG entrypoint for the isolated Cloud worker.

Password/HWID arrive over stdin, never argv/env/logs. HCX4 authenticates before
the historical HTTP Custom and HCCFG engines are considered.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from decoders.Python.HTTPCUSTOM import run as legacy_hc
from decoders.Python import _hc_hccfg as hccfg
from decoders.Python.apps.HTTP_Custom.codec import UnrecognizedFormat, decrypt as modern_hc
from decoders.Python._hc_legacy57 import decode as legacy57_hc

SAFE_ERRORS = {"PASSWORD_REQUIRED", "HWID_REQUIRED", "HWID_PASSWORD_REQUIRED", "AUTH_FAILED", "UNSUPPORTED_VERSION"}


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    try:
        raw = Path(sys.argv[1]).read_bytes()
        credentials = json.loads(sys.stdin.buffer.read(8192).decode("utf-8"))
        if not isinstance(credentials, dict) or not set(credentials) <= {"password", "hwid"}:
            return 2
        password = credentials.get("password")
        hwid = credentials.get("hwid")
        if password is not None and (not isinstance(password, str) or not 0 < len(password) <= 4096):
            return 2
        if hwid is not None and (not isinstance(hwid, str) or not 0 < len(hwid) <= 128):
            return 2
        try:
            clear = modern_hc(raw, password=password, hwid=hwid)
        except UnrecognizedFormat:
            pass
        else:
            sys.stdout.write(json.dumps(clear, ensure_ascii=False, indent=2) + "\n")
            return 0
        complete_legacy = legacy57_hc(raw)
        if complete_legacy is not None:
            sys.stdout.write(json.dumps(complete_legacy, ensure_ascii=False, indent=2) + "\n")
            return 0
        if password is None and hwid is None:
            # Existing legacy behaviour wins when no auth is required.
            try:
                original = legacy_hc(raw)
            except ValueError as error:
                # The original noninteractive bot wrapper converts a missing
                # HCCFG credential into ValueError; the Cloud HCCFG layer
                # must report the precise original HCError instead.
                if not str(error).startswith("HTTP Custom HCCFG: "):
                    raise
                original = None
            if isinstance(original, str) and original.strip():
                sys.stdout.write(original + "\n")
                return 0
        # A successful HCCFG result is authenticated before any JSON is shown.
        clear = hccfg.decrypt(raw, password=password, hwid=hwid)
        sys.stdout.write(json.dumps(clear, ensure_ascii=False, indent=2) + "\n")
        return 0
    except hccfg.HCError as error:
        code = str(error)
        if code.startswith("HWID_REQUIRED"):
            code = "HWID_REQUIRED"
        if code not in SAFE_ERRORS:
            code = "DECODE_FAILED"
        sys.stdout.write(json.dumps({"workerError": code}) + "\n")
        return 3
    except (OSError, ValueError, UnicodeError, TypeError):
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
