#!/usr/bin/env python3
"""CLI adapter: decode a .irfan file for the SP-DECODE C8 engine.

The engine runs ``python file_decoder.py <file>``; the adapter wraps
irfanvpn.decrypt_irfan_file (file -> dict) and prints exactly one JSON
document on stdout. Any failure exits 1 with the reason on stderr and
nothing on stdout, so the engine never parses a partial line.
"""
from __future__ import annotations

import json
import sys

if __package__:
    from .irfanvpn import decrypt_irfan_file
else:
    from irfanvpn import decrypt_irfan_file


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: file_decoder.py <file.irfan>", file=sys.stderr)
        return 2
    try:
        result = decrypt_irfan_file(sys.argv[1])
    except (OSError, ValueError) as exc:
        print("Unable to decode .irfan file: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
