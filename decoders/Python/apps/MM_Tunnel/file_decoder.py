#!/usr/bin/env python3
"""Read MM Tunnel .mmt profiles, preserving the historical Ultra/Sandok route."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from decoders.Python.apps.MM_Tunnel import codec


def run(data: bytes) -> str:
    codec.input_text(data)
    try:
        config = codec.decode_file(data)
    except codec.DecodeError as error:
        # The frozen C0 .mmt route also accepts historical Ultra/Sandok files.
        # Reuse it, including its output contract; do not change other suffixes.
        from decoders.Python import ultra
        config = ultra.decrypt_ultra_file(data, ".mmt")
        if config is None:
            raise codec.DecodeError("INVALID_MM_PROFILE") from error
        return codec.render({"application": ultra.ULTRA_NAMES[".mmt"],
                             "extension": ".mmt", "config": config})
    return codec.render({"application": "MM Tunnel", "extension": ".mmt", "config": config})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="Profile path, or - for stdin")
    args = parser.parse_args()
    try:
        if args.file == "-":
            data = sys.stdin.buffer.read(codec.MAX_BYTES + 1)
        else:
            with Path(args.file).open("rb") as stream:
                data = stream.read(codec.MAX_BYTES + 1)
        print(run(data))
        return 0
    except (OSError, ValueError, RecursionError):
        print("No se pudo leer el archivo MM Tunnel completo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
