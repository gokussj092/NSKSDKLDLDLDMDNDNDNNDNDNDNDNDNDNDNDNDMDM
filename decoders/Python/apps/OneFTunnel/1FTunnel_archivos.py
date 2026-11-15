#!/usr/bin/env python3
"""1FTunnel 0.7.1 — decodificador de archivos exportados (.1ftnl, backup JSON).

Lee archivos `.1ftnl` (texto `1FTnl.`/`1FT1.` o binario `1FT1`), grupos de
balanceo `1FTlb.`, backups `1FTunnel-backup-*.json` y enlaces `1ftunnel://`
pegados en un archivo de texto. Reutiliza el decodificador de 1FTunnel.py
(mismo directorio, stdlib puro).

Uso:
    python 1FTunnel_archivos.py perfil.1ftnl
    python 1FTunnel_archivos.py perfil.1ftnl --password Ghost
    cat perfil.1ftnl | python 1FTunnel_archivos.py -
    python 1FTunnel_archivos.py --self-test

Sin catálogo: la app no descarga ninguna lista de servidores (ver README.md).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import importlib.util

_spec = importlib.util.spec_from_file_location(
    "ftunnel_decoder", Path(__file__).resolve().parent / "1FTunnel.py")
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
DecodeError, decode, _self_test = _mod.DecodeError, _mod.decode, _mod._self_test


def run(data: bytes, *, password: str | None = None) -> str:
    return json.dumps(decode(data, password=password),
                      ensure_ascii=False, indent=2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", help="archivo a decodificar, "
                        "o - para stdin")
    parser.add_argument("--password", default=None,
                        help="contraseña (solo lockMode 2 / locked-v2)")
    parser.add_argument("--self-test", action="store_true",
                        help="vectores de prueba y salir")
    args = parser.parse_args()
    if args.self_test:
        return 0 if _self_test() else 1
    if not args.file:
        parser.error("falta el archivo (o - para stdin)")
    try:
        if args.file == "-":
            data = sys.stdin.buffer.read(5 * 1024 * 1024 + 1)
        else:
            with Path(args.file).open("rb") as stream:
                data = stream.read(5 * 1024 * 1024 + 1)
        print(run(data, password=args.password))
    except DecodeError as error:
        print(error.code, file=sys.stderr)
        return 2
    except (OSError, ValueError, UnicodeError):
        print("INVALID_INPUT", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
