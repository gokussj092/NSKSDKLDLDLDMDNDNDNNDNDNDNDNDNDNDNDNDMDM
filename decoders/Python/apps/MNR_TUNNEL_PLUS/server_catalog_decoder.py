#!/usr/bin/env python3
"""Offline worker for an entire MNR TUNNEL PLUS catalog."""
from pathlib import Path
import sys
if __package__:
    from .codec import MAX_BYTES, decode_catalog, render
else:
    from codec import MAX_BYTES, decode_catalog, render

def run(data: bytes) -> str:
    return render(decode_catalog(data))

def main():
    try:
        if len(sys.argv) != 2: return 2
        if sys.argv[1] == '-': data = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            with Path(sys.argv[1]).open('rb') as stream: data = stream.read(MAX_BYTES + 1)
        sys.stdout.write(run(data))
        return 0
    except (OSError, ValueError):
        print('No se pudo abrir el catálogo MNR completo.', file=sys.stderr)
        return 1

if __name__ == '__main__': raise SystemExit(main())
