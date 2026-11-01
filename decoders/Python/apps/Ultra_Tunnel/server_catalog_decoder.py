#!/usr/bin/env python3
"""Ultra Tunnel build 59: fixed original updater or an explicit offline input."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys
from urllib.request import HTTPRedirectHandler, Request, build_opener

if __package__:
    from .codec import DecodeError, MAX_BYTES, decode_catalog, render
else:
    from codec import DecodeError, MAX_BYTES, decode_catalog, render

SOURCE = "https://strongteam.co/api/ultrasystem/ultrav3.txt"
USER_AGENT = "Ultra Tunnel"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise DecodeError("La fuente Ultra Tunnel intentó redirigir la descarga.")


def download() -> bytes:
    try:
        request = Request(SOURCE, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"})
        with build_opener(_NoRedirect()).open(request, timeout=25) as response:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise DecodeError("Respuesta Ultra Tunnel incompatible.")
            data = response.read(MAX_BYTES + 1)
        if not data or len(data) > MAX_BYTES or data.lstrip().startswith((b"<", b"{")):
            raise DecodeError("La fuente no entregó el catálogo cifrado Ultra Tunnel.")
        return data
    except OSError as error:
        raise DecodeError("No se pudo descargar el catálogo Ultra Tunnel.") from error


def run(data: bytes) -> str:
    return render(decode_catalog(data))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument("file", nargs="?", type=Path)
    inputs.add_argument("--stdin", action="store_true")
    inputs.add_argument("--download", action="store_true", help="GET original fijo (también predeterminado)")
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
    except (ValueError, OSError, RecursionError):
        print("No se pudo leer el catálogo Ultra Tunnel completo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
