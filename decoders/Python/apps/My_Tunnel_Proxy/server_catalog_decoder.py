#!/usr/bin/env python3
"""My Tunnel Proxy 2.3: fetch its fixed catalog, or decode a local .js/.rj copy."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
from urllib.request import Request, HTTPRedirectHandler, build_opener

if __package__:
    from .codec import DecodeError, MAX_BYTES, envelope, render
else:
    from codec import DecodeError, MAX_BYTES, envelope, render

CATALOG_URL = "https://mfmpro.xyz/api/app?json=3c9a2a29f3a4180271da"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DecodeError("El proveedor intentó redirigir la descarga.")


def download() -> bytes:
    request = Request(CATALOG_URL, headers={"User-Agent": "My Tunnel Proxy/2.3", "Accept-Encoding": "identity"})
    try:
        with build_opener(_NoRedirect()).open(request, timeout=25) as response:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise DecodeError("Respuesta remota inválida.")
            data = response.read(MAX_BYTES + 1)
    except OSError as exc:
        raise DecodeError("No se pudo descargar el catálogo autorizado.") from exc
    if not data or len(data) > MAX_BYTES:
        raise DecodeError("Catálogo vacío o superior a 8 MiB.")
    return data


def run(data: bytes) -> str:
    """Pure offline worker entry point; network belongs to download()/Cloud broker."""
    return render(envelope(data, profile=False))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", type=Path, help="Copia cifrada .js/.rj; sin archivo descarga el catálogo")
    args = parser.parse_args()
    try:
        if args.file:
            with args.file.open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
        else:
            data = download()
        print(run(data))
        return 0
    except (OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, DecodeError) else "No se pudo leer el catálogo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
