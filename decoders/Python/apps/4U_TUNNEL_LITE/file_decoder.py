#!/usr/bin/env python3
"""4U TUNNEL LITE 2.2: archivos .4ulite y su contenido hexadecimal, sin red."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

# Native 4U xorWithKey was checked independently against the shared HX codec.
# The downloadable folder includes the unchanged shared source as a sidecar.
if Path(__file__).with_name("hxt_file_codec.py").is_file():
    import hxt_file_codec as _codec
else:
    for _root in Path(__file__).resolve().parents:
        if (_root / "decoders/Python/apps/HX_Tunnel_VPN/HX_Tunnel_VPN_archivos.py").is_file():
            if str(_root) not in sys.path:
                sys.path.insert(0, str(_root))
            from decoders.Python.apps.HX_Tunnel_VPN import HX_Tunnel_VPN_archivos as _codec
            break
    else:
        raise SystemExit("Falta hxt_file_codec.py; utiliza la carpeta completa del ZIP.")

MAX_BYTES = 8 * 1024 * 1024


class DecodeError(ValueError):
    """Errors never expose input values or lock metadata."""


def run(data: bytes) -> str:
    """Offline Cloud interface; preserve all stored fields and value types."""
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError("Entrada vacía o superior a 8 MiB.")
    try:
        text = data.decode("utf-8-sig").strip()
        if text.lower().startswith("4ulite://"):
            data = text[len("4ulite://"):].encode("ascii")
    except UnicodeError as exc:
        raise DecodeError("Texto de perfil inválido.") from exc
    result = _codec.run(data)
    if not isinstance(result, str):
        raise DecodeError("Archivo .4ulite de 4U inválido o incompatible.")
    obj = json.loads(result)
    if not obj or any(key in obj for key in ("Payloads", "Free_servers")):
        raise DecodeError("Se esperaba un tweak exportado de 4U.")
    if len(result.encode("utf-8")) > MAX_BYTES:
        raise DecodeError("La salida supera 8 MiB.")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", type=Path, help="Archivo .4ulite; omitir para leer stdin")
    args = parser.parse_args()
    try:
        with args.file.open("rb") if args.file else sys.stdin.buffer as stream:
            data = stream.read(MAX_BYTES + 1)
        sys.stdout.write(run(data))
        return 0
    except (OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, DecodeError) else "No se pudo leer el archivo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
