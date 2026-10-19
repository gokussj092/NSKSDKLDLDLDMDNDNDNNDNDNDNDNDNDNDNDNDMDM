#!/usr/bin/env python3
"""TRV TUNNEL 2.4: archivos .hxt y su contenido hexadecimal, sin red."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

# Native TRV xorWithKey was checked independently against the shared HX codec.
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
    result = _codec.run(data)
    if not isinstance(result, str):
        raise DecodeError("Archivo .hxt de TRV inválido o incompatible.")
    obj = json.loads(result)
    if (not isinstance(obj.get("friendly_name"), str) or
            not isinstance(obj.get("tweak_password"), str) or
            any(key in obj for key in ("Payloads", "Free_servers"))):
        raise DecodeError("Se esperaba un tweak exportado de TRV.")
    if len(result.encode("utf-8")) > MAX_BYTES:
        raise DecodeError("La salida supera 8 MiB.")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", type=Path, help="Archivo .hxt; omitir para leer stdin")
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
