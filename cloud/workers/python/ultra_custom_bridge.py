#!/usr/bin/env python3
"""Private Ultra Custom 5.2 file bridge with one-shot stdin credentials.

The canonical codec is unchanged. Never put passwords in argv, env, stdout
errors, logs, or the decoded output. Called only by the authenticated worker.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from decoders.Python.apps.Ultra_Custom import ultra_custom_52 as ultra


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    try:
        request = json.loads(sys.stdin.buffer.read(8193))
        if not isinstance(request, dict) or set(request) - {"password"}:
            return 2
        password = request.get("password")
        if password is not None and (not isinstance(password, str) or
                not 0 < len(password.encode("utf-8")) <= 4096):
            return 2
        raw = Path(sys.argv[1]).read_bytes()
        if not raw or len(raw) > ultra.MAX_BYTES:
            return 2
        result = ultra.decode(raw, password=password)
        sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        return 0
    except ultra.DecodeError as error:
        if error.code in ("PASSWORD_REQUIRED", "AUTH_FAILED"):
            sys.stdout.write(json.dumps({"workerError": error.code}))
            return 3
        return 1
    except (ValueError, TypeError, UnicodeError, OSError):
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
