#!/usr/bin/env python3
"""Standalone .awg reader. No user password is used by AboWaged 1.0's cipher."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
if __package__:
    from .codec import MAX_BYTES, decode_file, render
else:
    from codec import MAX_BYTES, decode_file, render


def run(data: bytes) -> str:
    return render(decode_file(data))


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
        print("No se pudo descifrar el archivo .awg completo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
