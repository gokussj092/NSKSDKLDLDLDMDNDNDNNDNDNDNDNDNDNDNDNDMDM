#!/usr/bin/env python3
"""CLI adapter: decode a .txtunnel file for the SP-DECODE C8 engine.

The engine runs ``python txtunnel_file_decoder.py <file>``. This
adapter exists because txtunnel.py's own main() prints progress lines
to stdout before the JSON, which would break the engine's json.loads;
import_txtunnel_content returns the decoded document cleanly and this
file prints exactly one JSON document on stdout. Any failure exits 1
with the reason on stderr and nothing on stdout.
"""
from __future__ import annotations

import json
import sys

if __package__:
    from .txtunnel import import_txtunnel_content
else:
    from txtunnel import import_txtunnel_content


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: txtunnel_file_decoder.py <file.txtunnel>", file=sys.stderr)
        return 2
    try:
        with open(sys.argv[1], "r", encoding="utf-8-sig") as stream:
            content = stream.read()
    except OSError as exc:
        print("Cannot read file: %s" % exc, file=sys.stderr)
        return 1
    try:
        result, _route = import_txtunnel_content(content)
    except (ValueError, TypeError) as exc:
        print("Unable to decode .txtunnel file: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
