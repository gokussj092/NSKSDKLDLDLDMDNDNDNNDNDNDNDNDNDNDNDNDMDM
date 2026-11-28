#!/usr/bin/env python3
"""Engine entry point for Ultra Custom 15.7 .ucs subscription files.

Thin adapter over ultra_custom.py (no new crypto, no network: --url
fetching is never used here). The engine runs
``[python, file_decoder.py, input.ucs]`` and passes credentials as JSON
on stdin (``{"password": ...}``), exactly like the Sentinel .st file
decoder. A .ucs document is JSON (``{"format": "CSS1", ...}``); a
password only unlocks UAP1-locked member profiles, one member at a
time, and decode_ucs() reports locked members as ``profile_error``
instead of raising, so a file-level PASSWORD_REQUIRED never occurs
for .ucs (documented in the CAT 103 report). A signature or format
failure is exit 1 (the engine reports DECODE_FAILED).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

if __package__:
    from .ultra_custom import DecodeError, decode_ucs
else:
    from ultra_custom import DecodeError, decode_ucs


def _read_password() -> str | None:
    """One-shot stdin credentials ({} when the worker sent none)."""
    try:
        raw = sys.stdin.buffer.read(8193)
    except OSError:
        return None
    if not raw:
        return None
    try:
        request = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(request, dict) or set(request) - {"password"}:
        return None
    password = request.get("password")
    return password if isinstance(password, str) and password else None


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    password = _read_password()
    try:
        raw = Path(sys.argv[1]).read_bytes()
    except OSError:
        return 2
    stripped = raw.lstrip()
    if stripped.startswith(b"\xef\xbb\xbf"):
        stripped = stripped[3:]
    if not stripped.startswith(b"{"):
        return 1
    try:
        result = decode_ucs(stripped, password=password)
    except DecodeError as error:
        # decode_ucs() never raises PASSWORD_REQUIRED (locked members
        # surface as per-server profile_error); keep the exit-3 branch
        # for contract symmetry in case a future member check raises.
        if error.code in ("PASSWORD_REQUIRED", "AUTH_FAILED"):
            sys.stdout.write(json.dumps({"workerError": error.code}))
            return 3
        return 1
    sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
