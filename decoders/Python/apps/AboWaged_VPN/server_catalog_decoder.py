#!/usr/bin/env python3
"""AboWaged's fixed main catalog and its separate UDP picker. Offline run()."""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path
import sys
from urllib.request import Request, HTTPRedirectHandler, build_opener
if __package__:
    from .codec import DecodeError, MAX_BYTES, _input, _json, decode_catalog, decode_udp, render
else:
    from codec import DecodeError, MAX_BYTES, _input, _json, decode_catalog, decode_udp, render

SOURCES = {
    "servers": "https://raw.githubusercontent.com/th3fre/Testing/refs/heads/main/Elk.txt",
    "udp": "https://raw.githubusercontent.com/janatshaban/REMOTEUPDATER/refs/heads/main/pickerver",
}
BUNDLE_KIND = "spdecode-abowaged-vpn-catalogs-v1"


def pack_catalogs(servers: bytes, udp: bytes) -> bytes:
    if any(not isinstance(v, bytes) or not v or len(v) > MAX_BYTES for v in (servers, udp)):
        raise DecodeError("Fuentes de catálogo inválidas.")
    data = json.dumps({"kind": BUNDLE_KIND, "catalogs": {
        "servers": base64.b64encode(servers).decode("ascii"),
        "udp": base64.b64encode(udp).decode("ascii"),
    }}, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_BYTES:
        raise DecodeError("Fuentes superiores a 8 MiB.")
    return data


def run(data: bytes) -> str:
    text = _input(data)
    if text.startswith("{"):
        obj = _json(text)
        if (not isinstance(obj, dict) or set(obj) != {"kind", "catalogs"} or
                obj["kind"] != BUNDLE_KIND or not isinstance(obj["catalogs"], dict) or
                set(obj["catalogs"]) != {"servers", "udp"}):
            raise DecodeError("Bundle de catálogo inválido.")
        sources = {}
        for name, method in (("servers", decode_catalog), ("udp", decode_udp)):
            encoded = obj["catalogs"][name]
            if not isinstance(encoded, str):
                raise DecodeError("Fuente Base64 inválida.")
            try:
                raw = base64.b64decode(encoded, validate=True)
            except ValueError as exc:
                raise DecodeError("Fuente Base64 inválida.") from exc
            sources[name] = method(raw)
        return render({"provider": "abowaged-vpn", "complete": True, "catalogs": sources})
    return render(decode_udp(data) if text.startswith("[") else decode_catalog(data))


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DecodeError("Redirección de proveedor no permitida.")


def download(source="servers") -> bytes:
    if source not in SOURCES:
        raise DecodeError("Fuente no permitida.")
    request = Request(SOURCES[source], headers={
        "User-Agent": "AboWaged VPN/1.0", "Accept-Encoding": "identity",
    })
    try:
        with build_opener(_NoRedirect()).open(request, timeout=25) as response:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise DecodeError("Respuesta remota inválida.")
            data = response.read(MAX_BYTES + 1)
    except OSError as exc:
        raise DecodeError("No se pudo descargar la fuente autorizada.") from exc
    if not data or len(data) > MAX_BYTES:
        raise DecodeError("Fuente vacía o demasiado grande.")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("file", nargs="?", type=Path)
    modes.add_argument("--stdin", action="store_true")
    modes.add_argument("--source", choices=tuple(SOURCES), help="Download one fixed source only")
    args = parser.parse_args()
    try:
        if args.file:
            with args.file.open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
        elif args.stdin:
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        elif args.source:
            data = download(args.source)
        else:
            data = pack_catalogs(download("servers"), download("udp"))
        sys.stdout.write(run(data))
        return 0
    except (OSError, ValueError):
        print("No se pudo leer el catálogo completo de AboWaged VPN.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
