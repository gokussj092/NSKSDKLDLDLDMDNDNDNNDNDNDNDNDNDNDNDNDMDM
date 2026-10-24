#!/usr/bin/env python3
"""Offline Aura Net catalog worker; downloading belongs to the broker/codec CLI."""
from __future__ import annotations
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from decoders.Python.apps.Aura_Net_VPN.codec import MAX_BYTES, decode_catalog, render


def run(data: bytes) -> str:
    return render(decode_catalog(data))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="Catalog path, or - for stdin")
    args = parser.parse_args()
    try:
        if args.file == "-":
            data = sys.stdin.buffer.read(MAX_BYTES+1)
        else:
            with Path(args.file).open("rb") as stream:
                data = stream.read(MAX_BYTES+1)
        print(run(data))
    except (ValueError, OSError, RecursionError):
        print("No se pudo leer el catálogo Aura Net completo.", file=sys.stderr)
        raise SystemExit(1)
