#!/usr/bin/env python3
"""Offline .stp / copied ciphertext reader. No external user password."""
from pathlib import Path
import sys
if __package__:
    from .codec import MAX_BYTES, decode_profile, render
else:
    from codec import MAX_BYTES, decode_profile, render

def run(data: bytes) -> str:
    return render(decode_profile(data))

def main():
    try:
        if len(sys.argv) != 2: return 2
        if sys.argv[1] == '-': data = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            with Path(sys.argv[1]).open('rb') as stream: data = stream.read(MAX_BYTES + 1)
        sys.stdout.write(run(data))
        return 0
    except (OSError, ValueError):
        print('No se pudo abrir el perfil MNR completo.', file=sys.stderr)
        return 1

if __name__ == '__main__': raise SystemExit(main())
