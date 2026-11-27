#!/usr/bin/env python3
"""TunelGuard VPN 17.7: descarga fija y descifrado del catálogo completo.

Build 177 source validated live 2026-11-27 (Version 5.0, config_revision 50,
90 servers, 1058 tweaks). Changes vs 12.8:

- Catalog URL moved: https://raw.githubusercontent.com/guruzgh-ed/edd/refs/heads/main/tg.js
  (was https://raw.githubusercontent.com/eddyme23/octo/refs/heads/main/xxTG.js).
- Envelope is STGCM3 (v3 key) with TGCR1 per-field values; STGCM2 still opens.
- Download matches the app (class iy0): plain GET, no custom headers, follow
  redirects, 15 s connect / 20 s read, max 8 MB, CR/LF stripped from the body.
  Conditional If-None-Match / If-Modified-Since only on repeat fetches.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys
from urllib.request import Request, build_opener

if __package__:
    from .codec import DecodeError, MAX_BYTES, decode_catalog, render
else:
    from codec import DecodeError, MAX_BYTES, decode_catalog, render

CATALOG_URL = "https://raw.githubusercontent.com/guruzgh-ed/edd/refs/heads/main/tg.js"


def run(data: bytes) -> str:
    """Offline entry point: downloading is confined to the CLI."""
    return render(decode_catalog(data))


def download() -> bytes:
    request = Request(CATALOG_URL, method="GET")
    try:
        with build_opener().open(request, timeout=20) as response:
            if response.status != 200:
                raise DecodeError("Respuesta remota inválida.")
            data = response.read(MAX_BYTES + 1)
    except OSError as exc:
        raise DecodeError("No se pudo descargar el catálogo de TunelGuard.") from exc
    if not data or len(data) > MAX_BYTES:
        raise DecodeError("Catálogo vacío o superior a 8 MiB.")
    if data.lstrip().startswith(b"<"):
        raise DecodeError("El proveedor devolvió una página web en lugar del catálogo cifrado.")
    return data.replace(b"\r", b"").replace(b"\n", b"")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument("file", nargs="?", type=Path, help="Copia cifrada local del catálogo")
    inputs.add_argument("--stdin", action="store_true", help="Leer el catálogo cifrado desde stdin")
    args = parser.parse_args()
    try:
        if args.file:
            with args.file.open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
        elif args.stdin:
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            data = download()
        print(run(data))
        return 0
    except (OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, DecodeError) else "No se pudo leer el catálogo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
