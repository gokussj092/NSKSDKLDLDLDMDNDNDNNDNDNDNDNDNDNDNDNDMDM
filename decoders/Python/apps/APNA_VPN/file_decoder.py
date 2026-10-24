#!/usr/bin/env python3
"""APNA 3.9 .apnavpn and apnavpn://, same source-derived profile primitive."""
import argparse
from pathlib import Path
import sys
if __package__:
    from .server_catalog_decoder import MAX_INPUT, decode_profile_bytes
else:
    from server_catalog_decoder import MAX_INPUT, decode_profile_bytes


def run(data: bytes) -> str:
    return decode_profile_bytes(data).decode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", type=Path)
    args = parser.parse_args()
    try:
        if args.file:
            with args.file.open("rb") as stream:
                data = stream.read(MAX_INPUT+1)
        else:
            data = sys.stdin.buffer.read(MAX_INPUT+1)
        print(run(data))
        return 0
    except (ValueError, OSError):
        print("Invalid or unsupported APNA profile", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
