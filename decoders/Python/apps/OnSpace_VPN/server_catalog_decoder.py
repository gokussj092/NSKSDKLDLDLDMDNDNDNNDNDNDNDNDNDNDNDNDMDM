#!/usr/bin/env python3
"""Download both OnSpace catalogs, or decode an existing encrypted copy."""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path
import sys
from urllib.request import Request, HTTPRedirectHandler, build_opener

if __package__:
    from .codec import DecodeError, MAX_BYTES, decode_catalog, render
else:
    from codec import DecodeError, MAX_BYTES, decode_catalog, render

# Original fixed NETWORK/NETWORK2 properties from res/raw/dnsd_conf.
CATALOG_URL = "https://raw.githubusercontent.com/El-Patron-Oficial2003/Metodos/refs/heads/main/OnSpace%20VPN"
USERS_URL = "https://raw.githubusercontent.com/El-Patron-Oficial2003/User-Pass-New/refs/heads/main/OnSpace%20VPN"
BUNDLE_KIND = "spdecode-onspace-vpn-catalogs-v1"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DecodeError("El proveedor intentó redirigir la descarga fija.")


def download(*, users=False) -> bytes:
    request = Request(USERS_URL if users else CATALOG_URL, headers={"User-Agent": "OnSpace VPN/4.2", "Accept-Encoding": "identity"})
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


def pack_catalogs(servers: bytes, users: bytes) -> bytes:
    for source in (servers, users):
        if not isinstance(source, bytes) or not source or len(source) > MAX_BYTES:
            raise DecodeError("Copia de catálogo vacía o superior al límite.")
    bundle = {"kind": BUNDLE_KIND, "catalogs": {
        "servers": base64.b64encode(servers).decode("ascii"),
        "users": base64.b64encode(users).decode("ascii"),
    }}
    data = json.dumps(bundle, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_BYTES:
        raise DecodeError("Los catálogos completos superan el límite del transporte.")
    return data


def decode_bundle(data: bytes) -> dict:
    try:
        if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
            raise DecodeError("Paquete de catálogos inválido.")
        bundle = json.loads(data, object_pairs_hook=_unique)
        if (not isinstance(bundle, dict) or set(bundle) != {"kind", "catalogs"}
                or bundle["kind"] != BUNDLE_KIND or not isinstance(bundle["catalogs"], dict)
                or set(bundle["catalogs"]) != {"servers", "users"}):
            raise DecodeError("Paquete de catálogos inválido.")
        decoded = {}
        for name, required in (("servers", "Servers"), ("users", "Usuarios")):
            encoded = bundle["catalogs"][name]
            if not isinstance(encoded, str):
                raise DecodeError("Copia de catálogo inválida.")
            raw = base64.b64decode(encoded, validate=True)
            doc = decode_catalog(raw)
            if required not in doc:
                raise DecodeError("La fuente no corresponde al catálogo esperado.")
            decoded[name] = doc
        return {"provider": "onspace-vpn", "complete": True, "catalogs": decoded}
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise DecodeError("No se pudieron abrir ambos catálogos completos de OnSpace VPN.") from exc


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DecodeError("Paquete de catálogos ambiguo.")
        result[key] = value
    return result


def run(data: bytes) -> str:
    """Offline entry point for a raw copy or the fixed server+user bundle."""
    if isinstance(data, bytes) and data.lstrip().startswith(b"{"):
        return render(decode_bundle(data))
    return render(decode_catalog(data))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("file", nargs="?", type=Path, help="Copia cifrada local de servidores o usuarios")
    modes.add_argument("--stdin", action="store_true", help="Leer una copia cifrada sin red")
    modes.add_argument("--download", action="store_true", help="Descargar únicamente los servidores")
    modes.add_argument("--users", action="store_true", help="Descargar únicamente los usuarios")
    modes.add_argument("--all", action="store_true", help="Descargar ambos catálogos completos (predeterminado)")
    args = parser.parse_args()
    try:
        if args.file:
            with args.file.open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
        elif args.stdin:
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        elif args.download or args.users:
            data = download(users=args.users)
        else:
            data = pack_catalogs(download(), download(users=True))
        print(run(data))
        return 0
    except (OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, DecodeError) else "No se pudo leer el catálogo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
