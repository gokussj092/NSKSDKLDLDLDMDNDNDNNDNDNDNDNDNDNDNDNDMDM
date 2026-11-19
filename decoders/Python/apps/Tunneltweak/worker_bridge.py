#!/usr/bin/env python3
"""Isolated .tut dispatcher: credentials on stdin and unchanged C0 fallback."""
from __future__ import annotations
import json
from pathlib import Path
import sys
from decoders.Python import generic_des
from decoders.Python.apps.Tunneltweak import codec, file_decoder


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
        # A Tunneltweak Cloud UUID returns JSON {config: <encrypted .tut>,
        # ...metadata}. Recognize that specific envelope before the legacy
        # generic-DES fallback, preserving the source's other fields and
        # supporting the authenticated TTPBE1 password challenge in RAM.
        # A normal .tut file is unchanged and cannot trigger network access.
        if data.lstrip(b"\xef\xbb\xbf \t\r\n").startswith(b"{"):
            try:
                envelope = json.loads(data.decode("utf-8-sig"))
            except (ValueError, UnicodeError):
                envelope = None
            if isinstance(envelope, dict) and "config" in envelope:
                sys.stdout.write(file_decoder.decode_cloud_response(
                    data, password=password) + "\n")
                return 0
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
