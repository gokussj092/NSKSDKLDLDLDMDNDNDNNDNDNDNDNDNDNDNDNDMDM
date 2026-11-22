#!/usr/bin/env python3
"""Complete fixed-source PM Tunnel Lite 1.0 catalog, without account access.

The catalog is a public GitHub Raw file fetched with a plain GET,
exactly as the app does it (Volley ``StringRequest``, GET, no headers,
no body — see the dossier ``ANALYSIS.md`` section 3). This CLI sends
no ``User-Agent`` and no ``Accept-Encoding`` header: the live
verification used plain ``curl`` and the plain ``urllib`` default and
both returned the identical bytes (SHA-256 ``d09b5d73…82d``), so the
result does not depend on headers. The broker-side ``agent`` proposed
in ``hunks.md`` (``"PM Tunnel Lite"``) follows the RENZ-family broker
pattern (GCP ``"GCP VPN"``, NetFlux ``"NetFlux VPN"``) and is a
broker presentation detail only.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
from urllib.request import Request, HTTPRedirectHandler, build_opener
if __package__:
    from .codec import CATALOG_URL, DecodeError, MAX_BYTES, decode_catalog, render
else:
    from codec import CATALOG_URL, DecodeError, MAX_BYTES, decode_catalog, render


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DecodeError("El proveedor intentó redirigir la descarga fija.")


def download() -> bytes:
    # Plain GET, no headers — exactly as the app fetches update.js.
    request = Request(CATALOG_URL)
    try:
        with build_opener(_NoRedirect()).open(request, timeout=25) as response:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise DecodeError("Respuesta remota inválida.")
            data = response.read(MAX_BYTES + 1)
    except OSError:
        raise DecodeError("No se pudo descargar el catálogo autorizado.") from None
    if not data or len(data) > MAX_BYTES or data.lstrip().startswith(b"<"):
        raise DecodeError("Catálogo remoto vacío o incompatible.")
    return data


def run(data: bytes) -> str:
    return render(decode_catalog(data))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    modes = p.add_mutually_exclusive_group()
    modes.add_argument("file", nargs="?", type=Path)
    modes.add_argument("--stdin", action="store_true")
    modes.add_argument("--download", action="store_true", help="Descargar la única fuente HTTPS fija (predeterminado)")
    a = p.parse_args()
    try:
        if a.file:
            with a.file.open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
        elif a.stdin:
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            data = download()
        sys.stdout.write(run(data))
        return 0
    except (OSError, ValueError):
        print("No se pudo leer el catálogo completo de PM Tunnel Lite.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
