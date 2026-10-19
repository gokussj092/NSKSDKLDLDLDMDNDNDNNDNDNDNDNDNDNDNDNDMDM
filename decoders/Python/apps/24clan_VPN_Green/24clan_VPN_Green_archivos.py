#!/usr/bin/env python3
"""24clan VPN Green 3.3: .green files and their encrypted text only.

Standalone Python 3.10+, standard library only; no network access.
For catalogs use 24clan_VPN_Green.py. See README.md in this directory.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import math
from pathlib import Path
import re
import struct
import sys

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
MASK = 0xffffffff
DELTA = (-1704280) & MASK  # Modified XXTEA; NOT the usual 0x9e3779b9.
# Shared client format constant used by both export and import.
PROFILE_KEY = b"technore_008515"


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _text(data: bytes | str) -> str:
    if not isinstance(data, (bytes, str)):
        raise DecodeError("FORMAT_ERROR", "Se esperaba texto o bytes UTF-8.")
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    try:
        value = data.decode("utf-8-sig") if isinstance(data, bytes) else data.removeprefix("\ufeff")
        if len(value.encode("utf-8")) > MAX_BYTES:
            raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    except UnicodeError as exc:
        raise DecodeError("FORMAT_ERROR", "La entrada no es UTF-8 válido.") from exc
    return value.strip()


def _base64(text: str) -> bytes:
    compact = re.sub(r"[ \t\r\n]", "", text)
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact) or len(compact) % 4 == 1:
        raise DecodeError("FORMAT_ERROR", "Se esperaba Base64 estándar de un archivo .green.")
    try:
        return base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DecodeError("FORMAT_ERROR", "Base64 inválido.") from exc


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _nonfinite(_value):
    raise ValueError("nonfinite number")


def _validate(doc):
    pending, count = [(doc, 0)], 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if depth > MAX_DEPTH or count > MAX_NODES:
            raise DecodeError("SIZE_LIMIT", "El JSON supera el límite de complejidad.")
        if isinstance(value, dict):
            pending.extend((v, depth + 1) for v in value.values())
            pending.extend((k, depth + 1) for k in value)
        elif isinstance(value, list):
            pending.extend((v, depth + 1) for v in value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise DecodeError("INVALID_JSON", "Número JSON no finito.")
        elif isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeError as exc:
                raise DecodeError("INVALID_JSON", "Unicode JSON inválido.") from exc
    return doc


def _json(data):
    try:
        doc = json.loads(data, object_pairs_hook=_unique, parse_constant=_nonfinite)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("INVALID_JSON", "JSON inválido o con claves duplicadas.") from exc
    if not isinstance(doc, dict):
        raise DecodeError("WRONG_DOCUMENT", "El perfil debe contener un objeto JSON.")
    return _validate(doc)


def _mx(total, y, z, position, e, key):
    return (((total ^ y) + (key[(position & 3) ^ e] ^ z))
            ^ (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))) & MASK


def decrypt_profile_bytes(data: bytes | str) -> bytes:
    encrypted = _base64(_text(data))
    if len(encrypted) < 8 or len(encrypted) % 4:
        raise DecodeError("TRUNCATED", "El archivo no contiene palabras XXTEA completas.")
    if encrypted.startswith(b"Salted__"):
        raise DecodeError("WRONG_DOCUMENT", "Este es un catálogo; utilice 24clan_VPN_Green.py.")
    values = list(struct.unpack("<" + "I" * (len(encrypted) // 4), encrypted))
    key = struct.unpack("<4I", PROFILE_KEY[:16].ljust(16, b"\0"))
    count = len(values)
    total = ((6 + 52 // count) * DELTA) & MASK
    y = values[0]
    while total:
        e = (total >> 2) & 3
        for position in range(count - 1, 0, -1):
            values[position] = (values[position] - _mx(total, y, values[position - 1], position, e, key)) & MASK
            y = values[position]
        values[0] = (values[0] - _mx(total, y, values[-1], 0, e, key)) & MASK
        y = values[0]
        total = (total - DELTA) & MASK
    length = values[-1]
    maximum = count * 4 - 4
    if not maximum - 3 <= length <= maximum:
        raise DecodeError("DECRYPT_FAILED", "La longitud interna XXTEA no es válida para esta aplicación.")
    return struct.pack("<" + "I" * (count - 1), *values[:-1])[:length]


def decode(data: bytes | str) -> dict:
    """Return every original field, including metadata and embedded JSON strings."""
    return _json(decrypt_profile_bytes(data))


def run(file_bytes: bytes | str) -> str | None:
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


def _read(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path, help="Archivo .green o texto cifrado guardado")
    source.add_argument("--text", help="Contenido Base64 de un perfil .green")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo; por defecto stdout")
    args = parser.parse_args(argv)
    try:
        result = decode(args.text if args.text is not None else _read(args.file))
        rendered = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        return 0
    except DecodeError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR", "message": "No se pudo leer o escribir el archivo."}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
