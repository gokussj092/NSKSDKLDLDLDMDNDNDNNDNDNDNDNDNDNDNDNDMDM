#!/usr/bin/env python3
"""TunelGuard VPN 12.8: lector actualizado y exclusivo de archivos .tgv."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

if __package__:
    from .codec import DecodeError, MAX_FILE_BYTES, decode_profile, render
else:
    from codec import DecodeError, MAX_FILE_BYTES, decode_profile, render


def run(data: bytes) -> str:
    """Offline Cloud entry point; no APK or repository imports required."""
    return render(decode_profile(data))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", type=Path, help="Archivo .tgv; omitir para leer stdin")
    args = parser.parse_args()
    try:
        with args.file.open("rb") if args.file else sys.stdin.buffer as stream:
            data = stream.read(MAX_FILE_BYTES + 1)
        print(run(data))
        return 0
    except (OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, DecodeError) else "No se pudo leer el archivo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
