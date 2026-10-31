#!/usr/bin/env python3
"""Decode JyFast VPN Ultra 9 SKS imports with the existing GCM/DES engine."""
from pathlib import Path
import argparse
import sys
if __package__:
    from .codec import DecodeError, MAX_FILE_BYTES, decode_profile, render
else:
    from codec import DecodeError, MAX_FILE_BYTES, decode_profile, render

def run(data: bytes) -> str:
    return render(decode_profile(data))

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', nargs='?', type=Path)
    args = parser.parse_args()
    try:
        if args.file:
            with args.file.open('rb') as stream:
                data = stream.read(MAX_FILE_BYTES + 1)
        else:
            data = sys.stdin.buffer.read(MAX_FILE_BYTES + 1)
        print(run(data))
        return 0
    except (OSError, ValueError):
        print('Archivo JyFast inválido o no compatible.', file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
