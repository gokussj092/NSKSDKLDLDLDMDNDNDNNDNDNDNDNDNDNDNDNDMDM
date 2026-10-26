#!/usr/bin/env python3
"""TunnelDOOM's bundled legacy SKS parser; reuse the verified canonical codec.

No independent export from build 424 was supplied or observed in its UI.
"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from decoders.Python.apps.HTTP_FenixVPN.codec import decode_profile, render, MAX_FILE_BYTES


def run(data: bytes) -> str:
    return render(decode_profile(data))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", type=Path)
    args = parser.parse_args()
    try:
        if args.file:
            with args.file.open("rb") as stream:
                data = stream.read(MAX_FILE_BYTES + 1)
        else:
            data = sys.stdin.buffer.read(MAX_FILE_BYTES + 1)
        print(run(data))
    except (ValueError, OSError):
        print("No se pudo leer el archivo SKS completo.", file=sys.stderr)
        raise SystemExit(1)
