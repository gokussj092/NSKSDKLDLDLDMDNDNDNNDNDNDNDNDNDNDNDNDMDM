#!/usr/bin/env python3
"""Isolated .tut dispatcher: credentials on stdin and unchanged C0 fallback."""
from __future__ import annotations
import json
from pathlib import Path
import sys
from decoders.Python import generic_des
from decoders.Python.apps.Tunneltweak import codec


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    try:
        data = Path(sys.argv[1]).read_bytes()
        credentials = json.loads(sys.stdin.buffer.read(65537).decode("utf-8"))
        if not isinstance(credentials, dict) or set(credentials) - {"password"}:
            return 2
        password = credentials.get("password")
        if password is not None:
            codec._password(password)
        # Preserve raw/Base64 DES and dot-separated generic GCM byte for byte.
        # The authenticated TTPBE1 format never reaches historical decoders.
        if not data.lstrip(b"\xef\xbb\xbf \t\r\n").startswith(b"TTPBE1:"):
            original = generic_des.run(data, ".tut")
            if original is not None:
                sys.stdout.write(original + "\n")
                return 0
        sys.stdout.write(codec.render(codec.decode_profile(data, password=password)) + "\n")
        return 0
    except (codec.PasswordRequired, codec.AuthFailed) as exc:
        sys.stdout.write(json.dumps({"workerError": str(exc)}) + "\n")
        return 3
    except (OSError, ValueError, UnicodeError, RecursionError):
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
