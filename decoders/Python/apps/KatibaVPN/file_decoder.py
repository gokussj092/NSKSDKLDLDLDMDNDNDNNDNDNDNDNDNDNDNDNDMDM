#!/usr/bin/env python3
"""CLI adapter: decode a .katiba file for the SP-DECODE C8 engine.

The engine runs ``python file_decoder.py <file>``; the adapter wraps
katiba.decrypt_file (Base64 envelope text -> JSON bytes) and prints
exactly one JSON document on stdout. Any failure exits 1 with the
reason on stderr and nothing on stdout, so the engine never parses a
partial line.

Like the catalog, a file may carry field values that do not decrypt
with the keys in the APK (see server_catalog_decoder.py); they are
kept verbatim in the output, never dropped.
"""
from __future__ import annotations

import json
import sys

if __package__:
    from .katiba import decrypt_file
else:
    from katiba import decrypt_file


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: file_decoder.py <file.katiba>", file=sys.stderr)
        return 2
    try:
        with open(sys.argv[1], "r", encoding="utf-8-sig") as stream:
            text = stream.read()
    except OSError as exc:
        print("Cannot read file: %s" % exc, file=sys.stderr)
        return 1
    try:
        raw = decrypt_file(text)
        result = json.loads(raw)
    except (ValueError, TypeError) as exc:
        print("Unable to decode .katiba file: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
