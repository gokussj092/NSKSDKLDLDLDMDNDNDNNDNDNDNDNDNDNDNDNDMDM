#!/usr/bin/env python3
"""MD PROXY VPN build29: fixed original updater or an explicit offline input."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys
from urllib.request import HTTPRedirectHandler, Request, build_opener

if __package__:
    from .codec import DecodeError, MAX_BYTES, decode_catalog, render
else:
    sys.path.insert(0,str(Path(__file__).resolve().parents[4]))
    from decoders.Python.apps.MD_Proxy_VPN.codec import DecodeError, MAX_BYTES, decode_catalog, render

SOURCE = "https://strongteam.co/api/ultrasystem/ultrav3.txt"
USER_AGENT = "MD PROXY VPN"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise DecodeError("La fuente MD PROXY VPN intentó redirigir la descarga.")


def download() -> bytes:
    try:
        request = Request(SOURCE, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"})
        with build_opener(_NoRedirect()).open(request, timeout=25) as response:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise DecodeError("Respuesta MD PROXY VPN incompatible.")
            data = response.read(MAX_BYTES + 1)
        if not data or len(data) > MAX_BYTES or data.lstrip().startswith((b"<", b"{")):
            raise DecodeError("La fuente no entregó el catálogo cifrado MD PROXY VPN.")
        return data
    except OSError as error:
        raise DecodeError("No se pudo descargar el catálogo MD PROXY VPN.") from error


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
        print("No se pudo leer el catálogo MD PROXY VPN completo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
