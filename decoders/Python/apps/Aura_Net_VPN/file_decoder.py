#!/usr/bin/env python3
"""AuraNet_v9 .aura, preserving the historical Ultra/Sandok file route."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from decoders.Python.apps.Aura_Net_VPN import codec


def run(data: bytes) -> str:
    try:
        outer = codec.open_document(data)
    except codec.EnvelopeError as error:
        from decoders.Python import ultra
        config = ultra.decrypt_ultra_file(data, ".aura")
        if config is None:
            raise codec.DecodeError("INVALID_AURA_PROFILE") from error
        return codec.render({"application": ultra.ULTRA_NAMES[".aura"], "extension": ".aura", "config": config})
    # Once the modern envelope authenticated, schema/inner failures must stop.
    config = codec.profile_document(outer)
    return codec.render({"application": "Aura Net VPN", "extension": ".aura", "config": config})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="Profile path, or - for stdin")
    args = parser.parse_args()
    try:
        if args.file == "-":
            data = sys.stdin.buffer.read(codec.MAX_BYTES+1)
        else:
            with Path(args.file).open("rb") as stream:
                data = stream.read(codec.MAX_BYTES+1)
        print(run(data))
        return 0
    except (ValueError, OSError, RecursionError):
        print("No se pudo leer el archivo Aura Net completo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
