#!/usr/bin/env python3
"""Download HTTP Jireh 2.2's fixed catalog; retain the 2.0 offline codec."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
from urllib.request import Request, HTTPRedirectHandler, build_opener

if __package__:
    from .codec import DecodeError, MAX_BYTES, decode_catalog, render
else:
    from codec import DecodeError, MAX_BYTES, decode_catalog, render

# HTTP Jireh 2.2 / build 13, res/raw/dnsd_conf NETWORK and NETWORK2.
# Dropbox's fixed raw-content host returns the encrypted bytes without redirects.
# Do not fall back to GitHub: that old source still returns a stale catalog.
CATALOG_URL = "https://dl.dropboxusercontent.com/scl/fi/9p6vvoa8jfch3ribneckq/HTTPJIREH1117?rlkey=05z97u9cg8tv4k5xem9m1uxu2&st=huezcplw&dl=1"
USERS_URL = "https://dl.dropboxusercontent.com/scl/fi/levagd0tny8izfpvgsilo/USUARIOSJIREH?rlkey=f4a0zwurd23nmk61ya6ptxf4u&st=bneujzqr&dl=1"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DecodeError("El proveedor intentó redirigir la descarga.")


def download(*, users=False) -> bytes:
    request = Request(USERS_URL if users else CATALOG_URL, headers={"User-Agent": "HTTP Jireh/2.2", "Accept-Encoding": "identity"})
    try:
        with build_opener(_NoRedirect()).open(request, timeout=25) as response:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise DecodeError("Respuesta remota inválida.")
            data = response.read(MAX_BYTES + 1)
    except OSError as exc:
        raise DecodeError("No se pudo descargar el catálogo autorizado.") from exc
    if not data or len(data) > MAX_BYTES or data.lstrip().startswith(b"<"):
        raise DecodeError("Catálogo remoto vacío, incompatible o superior a 8 MiB.")
    return data


def run(data: bytes) -> str:
    """Offline worker entry point for either original catalog type."""
    return render(decode_catalog(data))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", type=Path, help="Copia cifrada; sin archivo descarga los servidores")
    parser.add_argument("--stdin", action="store_true", help="Leer una copia cifrada sin red")
    parser.add_argument("--users", action="store_true", help="Descargar el catálogo separado de perfiles de usuario")
    args = parser.parse_args()
    if sum((bool(args.file), args.stdin, args.users)) > 1:
        parser.error("Elige archivo, --stdin o --users.")
    try:
        if args.file:
            with args.file.open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
        elif args.stdin:
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            data = download(users=args.users)
        print(run(data))
        return 0
    except (OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, DecodeError) else "No se pudo leer el catálogo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
