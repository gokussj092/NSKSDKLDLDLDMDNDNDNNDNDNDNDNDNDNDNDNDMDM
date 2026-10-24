#!/usr/bin/env python3
"""Offline .dtk entrypoint for the existing isolated file worker."""
import argparse
from pathlib import Path
import sys
if __package__:
    from .codec import MAX_BYTES, decode_profile, render
else:
    from codec import MAX_BYTES, decode_profile, render


def run(data: bytes) -> str:
    return render(decode_profile(data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    args = parser.parse_args()
    try:
        with args.file.open("rb") as stream:
            result = run(stream.read(MAX_BYTES+1))
        print(result)
        return 0
    except (ValueError, OSError):
        print("Archivo .dtk inválido o incompatible con ANY VPN.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
