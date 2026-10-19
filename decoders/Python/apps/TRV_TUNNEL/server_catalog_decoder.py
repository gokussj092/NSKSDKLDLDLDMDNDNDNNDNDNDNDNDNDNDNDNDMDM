#!/usr/bin/env python3
"""TRV TUNNEL 2.4: descarga fija y descifrado del catálogo completo."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
from urllib.request import HTTPRedirectHandler, Request, build_opener

# The same XXTEA primitive/key/delta were recovered from this APK's Java.
if Path(__file__).with_name("hxt_catalog_codec.py").is_file():
    import hxt_catalog_codec as _codec
else:
    for _root in Path(__file__).resolve().parents:
        if (_root / "decoders/Python/apps/HX_Tunnel_VPN/HX_Tunnel_VPN.py").is_file():
            if str(_root) not in sys.path:
                sys.path.insert(0, str(_root))
            from decoders.Python.apps.HX_Tunnel_VPN import HX_Tunnel_VPN as _codec
            break
    else:
        raise SystemExit("Falta hxt_catalog_codec.py; utiliza la carpeta completa del ZIP.")

MAX_BYTES = 8 * 1024 * 1024
CATALOG_URL = "https://trmrelay.store/updater/b67b57c85f49c34ee09fd87f2d6915"
LIST_FIELDS = ("Free_servers", "Premium_servers", "Vip_servers", "Private_servers", "Payloads")


class DecodeError(ValueError):
    """Errors never contain remote bodies or provider credentials."""


def run(data: bytes) -> str:
    """Offline Cloud entry point; never download or merge private local tweaks."""
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError("Entrada vacía o superior a 8 MiB.")
    result = _codec.run(data)
    if not isinstance(result, str):
        raise DecodeError("Catálogo de TRV inválido o incompatible.")
    obj = json.loads(result)
    if (not isinstance(obj.get("Version"), str) or not obj["Version"] or
            any(not isinstance(obj.get(key), list) for key in LIST_FIELDS)):
        raise DecodeError("Estructura del catálogo TRV incompatible.")
    if len(result.encode("utf-8")) > MAX_BYTES:
        raise DecodeError("La salida supera 8 MiB.")
    return result


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DecodeError("El proveedor intentó redirigir la descarga.")


def download() -> bytes:
    request = Request(CATALOG_URL, headers={
        "User-Agent": "TRV TUNNEL/2.4", "Accept-Encoding": "identity",
    })
    try:
        with build_opener(_NoRedirect()).open(request, timeout=25) as response:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise DecodeError("Respuesta remota inválida.")
            data = response.read(MAX_BYTES + 1)
    except OSError as exc:
        raise DecodeError("No se pudo descargar el catálogo de TRV.") from exc
    if not data or len(data) > MAX_BYTES:
        raise DecodeError("Catálogo vacío o superior a 8 MiB.")
    if data.lstrip().startswith(b"<"):
        raise DecodeError("El proveedor devolvió HTML en lugar del catálogo cifrado.")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument("file", nargs="?", type=Path, help="Copia cifrada local del catálogo")
    inputs.add_argument("--stdin", action="store_true", help="Leer una copia cifrada desde stdin")
    args = parser.parse_args()
    try:
        if args.file:
            with args.file.open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
        elif args.stdin:
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            data = download()
        sys.stdout.write(run(data))
        return 0
    except (OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, DecodeError) else "No se pudo leer el catálogo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
