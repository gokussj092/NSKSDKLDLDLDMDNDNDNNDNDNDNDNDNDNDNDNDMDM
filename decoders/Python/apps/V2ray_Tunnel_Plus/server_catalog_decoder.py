#!/usr/bin/env python3
"""Download both V2ray Tunnel Plus catalogs, or decode an existing subscription copy."""
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

# Primary sources declared by FreeServersActivity; caller URLs are never accepted.
BASE64_URL = "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt"
RAW_URL = "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt"
BUNDLE_KIND = "spdecode-v2ray-tunnel-plus-catalogs-v1"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DecodeError("El proveedor intentó redirigir la descarga fija.")


def download(*, raw=False) -> bytes:
    request = Request(RAW_URL if raw else BASE64_URL, headers={"User-Agent": "V2ray Tunnel Plus/10.0.0", "Accept-Encoding": "identity"})
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


def pack_catalogs(base64_source: bytes, raw_source: bytes) -> bytes:
    for source in (base64_source, raw_source):
        if not isinstance(source, bytes) or not source or len(source) > MAX_BYTES:
            raise DecodeError("Copia de catálogo vacía o superior al límite.")
    bundle = {"kind": BUNDLE_KIND, "catalogs": {
        "base64": base64.b64encode(base64_source).decode("ascii"),
        "raw": base64.b64encode(raw_source).decode("ascii"),
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
                or set(bundle["catalogs"]) != {"base64", "raw"}):
            raise DecodeError("Paquete de catálogos inválido.")
        decoded = {}
        for name, encoding in (("base64", "base64"), ("raw", "plain")):
            encoded = bundle["catalogs"][name]
            if not isinstance(encoded, str):
                raise DecodeError("Copia de catálogo inválida.")
            raw = base64.b64decode(encoded, validate=True)
            doc = decode_catalog(raw, expected_encoding=encoding)
            decoded[name] = doc
        return {"provider": "v2ray-tunnel-plus", "complete": True, "catalogs": decoded}
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise DecodeError("No se pudieron abrir ambos catálogos completos de V2ray Tunnel Plus.") from exc


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DecodeError("Paquete de catálogos ambiguo.")
        result[key] = value
    return result


def run(data: bytes) -> str:
    """Offline entry point for a raw copy or the fixed Base64+raw bundle."""
    if isinstance(data, bytes) and data.lstrip().startswith(b"{"):
        return render(decode_bundle(data))
    return render(decode_catalog(data))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("file", nargs="?", type=Path, help="Copia local de la suscripción")
    modes.add_argument("--stdin", action="store_true", help="Leer una copia de suscripción sin red")
    modes.add_argument("--base64", action="store_true", help="Descargar únicamente la fuente Base64")
    modes.add_argument("--raw", action="store_true", help="Descargar únicamente la fuente en texto")
    modes.add_argument("--all", action="store_true", help="Descargar ambos catálogos completos (predeterminado)")
    args = parser.parse_args()
    try:
        if args.file:
            with args.file.open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
        elif args.stdin:
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        elif args.base64 or args.raw:
            data = download(raw=args.raw)
        else:
            data = pack_catalogs(download(), download(raw=True))
        print(run(data))
        return 0
    except (OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, DecodeError) else "No se pudo leer el catálogo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
