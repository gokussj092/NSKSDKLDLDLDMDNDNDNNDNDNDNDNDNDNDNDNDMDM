#!/usr/bin/env python3
"""Standalone .1ftnl reader; --password-stdin keeps passwords out of argv."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

if __package__:
    from .codec import DecodeError, decode
else:
    from codec import DecodeError, decode


def run(data: bytes, *, password: str | None = None) -> str:
    return json.dumps(decode(data, password=password), ensure_ascii=False, indent=2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="profile path, or - for stdin")
    parser.add_argument("--password-stdin", action="store_true", help="read a JSON password object from stdin")
    args = parser.parse_args()
    try:
        if args.password_stdin and args.file == "-":
            raise DecodeError("INVALID_INPUT")
        password = None
        if args.password_stdin:
            # JSON escaping can expand a 4096-byte password sixfold.
            incoming = sys.stdin.buffer.read(32769)
            require_credentials = json.loads(incoming)
            if (len(incoming) > 32768 or not isinstance(require_credentials, dict) or
                    set(require_credentials) - {"password"}):
                raise DecodeError("INVALID_CREDENTIALS")
            password = require_credentials.get("password")
            if password is not None and (not isinstance(password, str) or
                    not 0 < len(password.encode("utf-8")) <= 4096):
                raise DecodeError("INVALID_CREDENTIALS")
        if args.file == "-":
            data = sys.stdin.buffer.read(5 * 1024 * 1024 + 1)
        else:
            with Path(args.file).open("rb") as stream:
                data = stream.read(5 * 1024 * 1024 + 1)
        output = run(data, password=password)
    except (OSError, ValueError, UnicodeError) as error:
        code = error.code if isinstance(error, DecodeError) else "INVALID_INPUT"
        if args.password_stdin and code in ("PASSWORD_REQUIRED", "AUTH_FAILED"):
            print(json.dumps({"workerError": code}))
            return 3
        print(code, file=sys.stderr)
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
