#!/usr/bin/env python3
"""TunelGuard VPN 12.8: descarga fija y descifrado del catálogo completo."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
from urllib.request import HTTPRedirectHandler, Request, build_opener

if __package__:
    from .codec import DecodeError, MAX_BYTES, decode_catalog, render
else:
    from codec import DecodeError, MAX_BYTES, decode_catalog, render

CATALOG_URL = "https://raw.githubusercontent.com/eddyme23/octo/refs/heads/main/xxTG.js"


def run(data: bytes) -> str:
    """Offline entry point: downloading is confined to the CLI."""
    return render(decode_catalog(data))


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DecodeError("El proveedor intentó redirigir la descarga.")


def download() -> bytes:
    request = Request(CATALOG_URL, headers={
        "User-Agent": "Royal Tunnel VPN/7.0", "Accept-Encoding": "identity",
    })
    try:
        with build_opener(_NoRedirect()).open(request, timeout=25) as response:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise DecodeError("Respuesta remota inválida.")
            data = response.read(MAX_BYTES + 1)
    except OSError as exc:
        raise DecodeError("No se pudo descargar el catálogo de TunelGuard.") from exc
    if not data or len(data) > MAX_BYTES:
        raise DecodeError("Catálogo vacío o superior a 8 MiB.")
    if data.lstrip().startswith(b"<"):
        raise DecodeError("El proveedor devolvió una página web en lugar del catálogo cifrado.")
    return data


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
