#!/usr/bin/env python3
"""CLI adapter: decode a .pulse file for the SP-DECODE C8 engine.

The engine runs ``python file_decoder.py <file>`` with the optional
password JSON on stdin (see cloud/workers/python/engine.py,
protected_pulse). Password-protected files use the TOURUX1P: format
(see pulsetunnel.decode_pulse); the plain format needs no password.

Output is exactly one JSON document on stdout (or a workerError
object on a password failure, exit code 3, following the XVEON
precedent); every other failure exits 1 with the reason on stderr
and nothing on stdout, so the engine never parses a partial line.
"""
from __future__ import annotations

import json
import sys

if __package__:
    from .pulsetunnel import decode_pulse
else:
    from pulsetunnel import decode_pulse


def _read_password() -> str | None:
    """Password from the engine's stdin JSON, if any."""
    try:
        if sys.stdin.isatty():
            return None
    except Exception:
        return None
    try:
        raw = sys.stdin.read()
    except Exception:
        return None
    if not raw or not raw.strip():
        return None
    try:
        payload = json.loads(raw)
    except ValueError:
        return None
    if isinstance(payload, dict):
        value = payload.get("password")
        if isinstance(value, str) and value:
            return value
    return None


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: file_decoder.py <file.pulse>", file=sys.stderr)
        return 2
    try:
        with open(sys.argv[1], "r", encoding="utf-8-sig") as stream:
            text = stream.read()
    except OSError as exc:
        print("Cannot read file: %s" % exc, file=sys.stderr)
        return 1
    try:
        result = decode_pulse(text, _read_password())
    except ValueError as exc:
        message = str(exc)
        if "contraseña" in message or "password" in message.lower():
            print(json.dumps({"workerError": "PASSWORD_REQUIRED"},
                             ensure_ascii=False))
            return 3
        print("Unable to decode .pulse file: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
