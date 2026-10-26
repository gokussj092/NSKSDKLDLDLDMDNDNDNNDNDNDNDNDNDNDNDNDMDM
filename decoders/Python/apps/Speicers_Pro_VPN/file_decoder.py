#!/usr/bin/env python3
"""Speicers 104.1.17 .sks: reuse the byte-identical canonical GCM/DES reader."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

if __package__:
    from ..HTTP_FenixVPN import codec
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from HTTP_FenixVPN import codec


def run(data: bytes) -> str:
    return codec.render(codec.decode_profile(data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    args = parser.parse_args()
    try:
        with args.file.open("rb") as stream:
            result = run(stream.read(codec.MAX_FILE_BYTES + 1))
        print(result)
        return 0
    except (OSError, ValueError):
        print("Archivo SKS inválido o incompatible con Speicers 104.1.17.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
