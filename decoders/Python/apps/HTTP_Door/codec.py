#!/usr/bin/env python3
"""HTTP Door 5.0 .kyz: raw DES/ECB/PKCS5Padding and Java Properties XML.

The repository shares its lossless XML parser with CREEB INJECTOR. The
Termux bundler embeds those exact functions; no APK or network is required.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import sys
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad

# BEGIN_SHARED_IMPORTS
if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from decoders.Python.apps.CREEB_INJECTOR.codec import (
    DecodeError, MAX_BYTES, decode_properties, render,
)
# END_SHARED_IMPORTS

# ConfigParser.KEY_PASSWORD = "cinbdf665$4"; DESKeySpec takes eight bytes.
DES_KEY = b"cinbdf66"


def decode(data: bytes) -> dict:
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError("Entrada vacía o superior a 8 MiB.")
    if len(data) % 8:
        raise DecodeError("Archivo .kyz incompleto.")
    try:
        xml = unpad(DES.new(DES_KEY, DES.MODE_ECB).decrypt(data), 8)
        result = decode_properties(xml)
        result["format"] = "http-door-des-properties"
        return result
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("Archivo inválido o incompatible con HTTP Door 5.0.") from exc


def run(data: bytes) -> str:
    return render(decode(data))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="Archivo .kyz o - para stdin")
    parser.add_argument("--output", "-o", type=Path, help="Guardar JSON privado sin sobrescribir")
    args = parser.parse_args()
    try:
        if args.file == "-":
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            with Path(args.file).open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
        output = run(data) + "\n"
        if args.output:
            with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as stream:
                stream.write(output)
        else:
            sys.stdout.write(output)
        return 0
    except (OSError, ValueError):
        print("No se pudo abrir el .kyz o guardar el JSON completo; no se sobrescriben archivos.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
