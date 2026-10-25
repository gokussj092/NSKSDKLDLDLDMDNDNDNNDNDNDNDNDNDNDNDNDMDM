#!/usr/bin/env python3
"""MTM Tunnel Lite MTM (40): complete catalogs, stdlib Python 3.10+."""
from __future__ import annotations
import argparse
from http.client import HTTPException
import json
import os
from pathlib import Path
import sys
from urllib.request import HTTPRedirectHandler, Request, build_opener

# BEGIN_SHARED_IMPORTS
from decoders.Python.apps.HX_Tunnel_VPN.HX_Tunnel_VPN import (
    DecodeError, _catalog_json, decrypt_catalog_bytes,
)
# END_SHARED_IMPORTS

MAX_INPUT = 8 * 1024 * 1024
CATALOG_KEY = b"Princie!"
CATALOG_URL = "https://xtmtunnel.xyz/updater/527543543860c45bf4238f2a1b56c3"
USER_AGENT = "Dalvik/2.1.0"


def decode_bytes(data: bytes | str) -> bytes:
    if not isinstance(data, (bytes, str)) or len(data) > MAX_INPUT:
        raise DecodeError("SIZE_LIMIT", "Entrada ausente o demasiado grande.")
    return decrypt_catalog_bytes(data, key=CATALOG_KEY)


def parse_catalog(plain: bytes) -> dict:
    doc = _catalog_json(plain)
    if (not isinstance(doc.get("Version"), str) or not doc["Version"]
            or "Free_servers" not in doc or "Payloads" not in doc):
        raise DecodeError("WRONG_DOCUMENT", "No es un catálogo MTM completo.")
    return doc


def decode(data: bytes | str) -> dict:
    return parse_catalog(decode_bytes(data))


def render(doc: dict) -> str:
    return json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"


def run(data: bytes | str) -> str | None:
    """Offline worker API; preserve every original field, including credentials."""
    try:
        return render(decode(data))
    except (ValueError, RecursionError):
        return None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def fetch_catalog() -> bytes:
    request = Request(CATALOG_URL, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"})
    with build_opener(_NoRedirect()).open(request, timeout=25) as response:
        if response.status != 200:
            raise ValueError("El servidor no devolvió el catálogo.")
        data = response.read(MAX_INPUT + 1)
    if not data or len(data) > MAX_INPUT:
        raise ValueError("Respuesta vacía o demasiado grande.")
    return data


def read_input(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read(MAX_INPUT + 1)
    with Path(path).open("rb") as stream:
        return stream.read(MAX_INPUT + 1)


def save(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", help="Catálogo cifrado .json/.v2; - lee texto de stdin")
    parser.add_argument("-o", "--output", type=Path, help="JSON de salida; nunca sobrescribe")
    parser.add_argument("--stdout", action="store_true", help="Mostrar JSON completo en la terminal")
    args = parser.parse_args(argv)
    if args.stdout and args.output:
        parser.error("Elige --stdout o --output.")
    try:
        text = render(decode(read_input(args.file) if args.file else fetch_catalog()))
        if args.stdout:
            sys.stdout.write(text)
        else:
            output = args.output or Path("mtm_catalogo.json")
            save(output, text)
            print(f"Catálogo completo guardado en {output}", file=sys.stderr)
    except (ValueError, OSError, HTTPException, RecursionError):
        print("No se pudo descargar, descifrar o guardar el catálogo completo. Revisa la entrada y usa una salida nueva.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
