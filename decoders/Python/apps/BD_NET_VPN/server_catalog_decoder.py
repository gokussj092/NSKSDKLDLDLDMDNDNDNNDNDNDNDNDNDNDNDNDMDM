#!/usr/bin/env python3
"""Offline BD NET catalog worker; the broker owns fixed-source downloading."""
from pathlib import Path
import sys

if __package__:
    from .codec import MAX_INPUT, run
else:
    from codec import MAX_INPUT, run


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="Catalog path, or - for stdin")
    args = parser.parse_args()
    try:
        if args.file == "-":
            data = sys.stdin.buffer.read(MAX_INPUT+1)
        else:
            with Path(args.file).open("rb") as source:
                data = source.read(MAX_INPUT+1)
        print(run(data))
    except (ValueError, OSError, RecursionError):
        print("No se pudo leer el catálogo BD NET completo.", file=sys.stderr)
        raise SystemExit(1)
