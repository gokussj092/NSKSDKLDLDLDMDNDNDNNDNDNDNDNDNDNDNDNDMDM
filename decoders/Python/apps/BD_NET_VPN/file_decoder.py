#!/usr/bin/env python3
"""BD NET PrinceBuild111 .bdnet and bdnet://; complete nested fields."""
from pathlib import Path
import sys

if __package__:
    from .codec import MAX_INPUT, decode_profile_bytes
else:
    from codec import MAX_INPUT, decode_profile_bytes


def run(data: bytes) -> str:
    return decode_profile_bytes(data).decode("utf-8")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="Profile path, or - for stdin")
    args = parser.parse_args()
    try:
        if args.file == "-":
            data = sys.stdin.buffer.read(MAX_INPUT+1)
        else:
            with Path(args.file).open("rb") as source:
                data = source.read(MAX_INPUT+1)
        print(run(data))
    except (ValueError, OSError, RecursionError):
        print("No se pudo leer el perfil BD NET completo.", file=sys.stderr)
        raise SystemExit(1)
