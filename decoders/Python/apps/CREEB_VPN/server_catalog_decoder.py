#!/usr/bin/env python3
"""Offline CREEB VPN 50.0 catalog reader. Remote download is unvalidated."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
if __package__:
    from .codec import MAX_BYTES, decode, render
else:
    from codec import MAX_BYTES, decode, render


def run(data: bytes) -> str:
    return render(decode(data, catalog=True))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("file", help="assets/data.creeb or official captured response; - for stdin")
    a = p.parse_args()
    try:
        if a.file == "-":
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            with Path(a.file).open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
        sys.stdout.write(run(data))
        return 0
    except (OSError, ValueError):
        print("No se pudo abrir el catálogo CREEB VPN completo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
