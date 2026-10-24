#!/usr/bin/env python3
"""Standalone .creeb reader for CREEB 38.0. No external password/HWID needed."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
if __package__:
    from .codec import MAX_BYTES, decode, render
else:
    from codec import MAX_BYTES, decode, render


def run(data: bytes) -> str:
    return render(decode(data))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="Profile path or - for stdin")
    args = parser.parse_args()
    try:
        if args.file == "-":
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            with Path(args.file).open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
        sys.stdout.write(run(data))
        return 0
    except (OSError, ValueError):
        print("No se pudo leer el archivo .creeb completo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
