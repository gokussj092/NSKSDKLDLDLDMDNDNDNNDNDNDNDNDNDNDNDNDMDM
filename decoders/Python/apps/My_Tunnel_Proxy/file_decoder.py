#!/usr/bin/env python3
"""My Tunnel Proxy 2.3: .mtp exports and mytunnelproxy:// text, offline."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

if __package__:
    from .codec import DecodeError, MAX_BYTES, cloud_reference, envelope, render
else:
    from codec import DecodeError, MAX_BYTES, cloud_reference, envelope, render


def run(data: bytes) -> str:
    return render(envelope(data, profile=True))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", type=Path, help="Archivo .mtp; omitir para leer stdin")
    parser.add_argument("--reference", action="store_true", help="Decodificar solo el identificador mytunnel://; sin descargar el perfil")
    args = parser.parse_args()
    try:
        with args.file.open("rb") if args.file else sys.stdin.buffer as stream:
            data = stream.read(MAX_BYTES + 1)
        print(render(cloud_reference(data)) if args.reference else run(data))
        return 0
    except (OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, DecodeError) else "No se pudo leer el archivo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
