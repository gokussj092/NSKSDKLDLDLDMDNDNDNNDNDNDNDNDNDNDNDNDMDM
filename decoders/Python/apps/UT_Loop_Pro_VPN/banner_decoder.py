#!/usr/bin/env python3
"""Optional offline reader for authorized UT Loop SSH greeting copies."""
from pathlib import Path
import argparse
import sys
if __package__:
    from .codec import decode_banner, MAX_BYTES
else:
    from codec import decode_banner, MAX_BYTES


def run(data: bytes) -> str:
    return decode_banner(data)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('file', nargs='?', type=Path, help='Omitir para leer stdin')
    a = p.parse_args()
    try:
        if a.file:
            with a.file.open('rb') as stream:
                data = stream.read(MAX_BYTES + 1)
        else:
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        sys.stdout.write(run(data))
        return 0
    except (ValueError, OSError):
        print('No se pudo autenticar o leer el banner.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
