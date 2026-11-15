#!/usr/bin/env python3
"""Hex Custom HXS3 file bridge: password arrives only on stdin, never argv.

Used by engine.py only when the input starts with the HXS3 v3 container
(see _is_hex_custom_v3). Old Hex Tunnel files keep their own route and
need no password. Maps the decoder's error codes onto the worker codes
engine.py understands.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))


def fail(code: str) -> int:
    sys.stdout.write(json.dumps({"workerError": code}))
    return 3


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    try:
        raw = Path(sys.argv[1]).read_bytes()
        payload = sys.stdin.buffer.read(8193)
        if len(payload) > 8192:
            return fail("INVALID_CREDENTIALS")
        credentials = json.loads(payload) if payload else {}
        if not isinstance(credentials, dict) or set(credentials) - {"password"}:
            return fail("INVALID_CREDENTIALS")
        password = credentials.get("password")
        if password is not None and (
            not isinstance(password, str)
            or not 0 < len(password.encode("utf-8")) <= 4096
        ):
            return fail("INVALID_CREDENTIALS")
    except (OSError, UnicodeError, ValueError):
        return fail("DECODE_FAILED")
    try:
        from decoders.Python.apps.Hex_Custom.Hex_Custom_archivos import (
            DecodeError,
            decode,
        )
    except Exception:
        return fail("ENGINE_UNAVAILABLE")
    try:
        result = decode(raw, password=password)
    except DecodeError as exc:
        if exc.code == "PASSWORD_REQUIRED":
            return fail("PASSWORD_REQUIRED")
        if exc.code == "WRONG_PASSWORD":
            return fail("AUTH_FAILED")
        if exc.code in ("UNSUPPORTED_FLAGS", "UNSUPPORTED_VERSION"):
            return fail("UNSUPPORTED_VERSION")
        return fail("DECODE_FAILED")
    except (ValueError, TypeError, RecursionError):
        return fail("DECODE_FAILED")
    sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
