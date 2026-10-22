#!/usr/bin/env python3
"""Read a SocketClay catalog copy; --download requests its fixed server source."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
from urllib.request import Request, HTTPRedirectHandler, build_opener

if __package__:
    from .codec import DecodeError, MAX_BYTES, decode_catalog, render
else:
    from codec import DecodeError, MAX_BYTES, decode_catalog, render

# APK SkProtect.updateURL. Remote response/redirect chain not yet validated;
# the public Cloud card deliberately has remote:null until that check succeeds.
CATALOG_URL = "https://www.dropbox.com/scl/fi/vh319xyu0ck84ks0wdqw8/ServersSC?rlkey=b9g57byy0igz2jitqix31t4i4&st=evmzpf11&dl=1"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DecodeError("La descarga requiere validar la redirección del proveedor.")


def download() -> bytes:
    request = Request(CATALOG_URL, headers={"User-Agent": "HTTP SocketClay/3.4.0", "Accept-Encoding": "identity"})
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
    """Offline worker entry point, never accesses the network."""
    return render(decode_catalog(data))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("file", nargs="?", type=Path, help="Copia cifrada local de servidores o usuarios")
    modes.add_argument("--stdin", action="store_true", help="Leer una copia cifrada sin red")
    modes.add_argument("--download", action="store_true", help="Consultar la fuente fija de servidores; validación remota pendiente")
    args = parser.parse_args()
    if not (args.file or args.stdin or args.download):
        parser.error("Indica un archivo, --stdin o --download.")
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
