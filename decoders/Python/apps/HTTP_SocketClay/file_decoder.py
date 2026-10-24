#!/usr/bin/env python3
"""Decode HTTP SocketClay 3.4.0 .sks files (GCM or legacy raw DES)."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

if __package__:
    from .codec import DecodeError, MAX_FILE_BYTES, decode_profile, render
else:
    from codec import DecodeError, MAX_FILE_BYTES, decode_profile, render


def run(data: bytes) -> str:
    return render(decode_profile(data))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", type=Path, help="Archivo .sks; sin archivo lee stdin")
    args = parser.parse_args()
    try:
        if args.file:
            with args.file.open("rb") as stream:
                data = stream.read(MAX_FILE_BYTES + 1)
        else:
            data = sys.stdin.buffer.read(MAX_FILE_BYTES + 1)
        print(run(data))
        return 0
    except (OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, DecodeError) else "No se pudo leer el archivo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
