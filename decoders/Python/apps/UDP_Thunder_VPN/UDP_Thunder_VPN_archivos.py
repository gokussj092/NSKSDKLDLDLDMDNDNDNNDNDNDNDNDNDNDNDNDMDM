#!/usr/bin/env python3
"""UDP Thunder VPN 1.5: file decoder (offline catalog file aug.json).

Python 3.10+, solo biblioteca estandar.

UDP Thunder VPN no tiene formato propio de perfil exportable/importable
(no hay intent-filter de archivos en el manifiesto, no hay esquema URI
propio y no hay picker de archivos en la app): los perfiles viven solo
dentro del catalogo. Lo unico que la app guarda como archivo es el
catalogo mismo, en filesDir/aug.json (o el asset incluido aug.json si
aun no se descargo nada). Este script descifra ese archivo con el
mismo metodo del catalogo (Base64 -> XXTEA modificado, clave "...|...").

Uso:
    python3 UDP_Thunder_VPN_archivos.py aug.json
    python3 UDP_Thunder_VPN_archivos.py --asset
    python3 UDP_Thunder_VPN_archivos.py --self-test

El decodificador se importa de UDP_Thunder_VPN.py (mantener juntos).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from UDP_Thunder_VPN import (  # noqa: E402
    ASSET_NAME,
    CatalogError,
    decode,
    decode_json_bytes,
)


def decode_file(data: bytes, keep_encoded: bool = False) -> dict:
    """Decrypt an aug.json file (Base64 -> XXTEA -> JSON) and return the dict."""
    return decode(data, keep_encoded=keep_encoded)


def run(data: bytes) -> str:
    """Return the decoded file as JSON text."""
    return json.dumps(decode_file(data), ensure_ascii=False, indent=2) + "\n"


def _self_test() -> dict:
    """Verify the bundled asset opens and a live catalog blob re-opens."""
    checks = {}
    asset = Path(__file__).with_name(ASSET_NAME)
    if asset.exists():
        doc = decode_file(asset.read_bytes())
        checks["asset_version"] = doc.get("Version") == "18.0"
        checks["asset_free_servers"] = len(doc.get("Free_servers", [])) == 25
        checks["asset_credentials_opened"] = (
            isinstance(doc.get("Username"), str) and doc["Username"] != ""
            and all(c.isprintable() for c in doc["Username"]))
    else:
        checks["asset_present"] = False
    try:
        decode_file(b"not base64!!!")
        checks["garbage_rejected"] = False
    except CatalogError:
        checks["garbage_rejected"] = True
    try:
        decode_file(b"aGVsbG8gd29ybGQ=")  # "hello world" is not XXTEA
        checks["plain_base64_rejected"] = False
    except CatalogError:
        checks["plain_base64_rejected"] = True
    return checks


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", type=Path,
                        help="Archivo aug.json guardado (Base64 cifrado) o JSON plano")
    parser.add_argument("--asset", action="store_true", help="Descifrar el aug.json incluido")
    parser.add_argument("--stdin", action="store_true", help="Leer el cuerpo cifrado desde stdin")
    parser.add_argument("--keep-encoded", action="store_true",
                        help="Dejar Username/Password como Base64 cifrado")
    parser.add_argument("--self-test", action="store_true", help="Verificar el asset incluido")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            result = _self_test()
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if all(result.values()) else 1
        if args.asset:
            raw = Path(__file__).with_name(ASSET_NAME).read_bytes()
        elif args.file is not None:
            raw = args.file.read_bytes()
        elif args.stdin:
            raw = sys.stdin.buffer.read(8 * 1024 * 1024 + 1)
        else:
            parser.error("se requiere un archivo, --asset o --stdin (o --self-test)")
        doc = decode_file(raw, keep_encoded=args.keep_encoded)
        rendered = json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        return 0
    except CatalogError as exc:
        print(json.dumps({"error": "CatalogError", "message": str(exc)}, ensure_ascii=False),
              file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR", "message": "No se pudo leer o escribir el archivo."}),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
