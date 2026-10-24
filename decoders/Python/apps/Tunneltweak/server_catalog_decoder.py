#!/usr/bin/env python3
"""Download the original Tunneltweak catalog and print all JSON, including metadata."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
if __package__:
    from .codec import DecodeError, MAX_BYTES, decode_catalog, render
    from .network import download
    from .file_decoder import read_secret
else:
    from codec import DecodeError, MAX_BYTES, decode_catalog, render
    from network import download
    from file_decoder import read_secret


def run(data: bytes, *, api_key: str | None = None) -> str:
    """Pure offline entry point; the Cloud broker alone performs the download."""
    return render(decode_catalog(data, api_key=api_key))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", type=Path, help="Copia local cifrada del catálogo")
    parser.add_argument("--stdin", action="store_true", help="Leer una copia cifrada sin red")
    parser.add_argument("--api-key-file", type=Path, help="Clave propia de suscripción, si el catálogo la necesita")
    args = parser.parse_args()
    if args.file and args.stdin:
        parser.error("Elige archivo o --stdin.")
    try:
        key = read_secret(args.api_key_file) if args.api_key_file else None
        if args.file:
            with args.file.open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
        elif args.stdin:
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            data = download(api_key=key)
        print(run(data, api_key=key))
        return 0
    except (OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, DecodeError) else "No se pudo leer el catálogo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
