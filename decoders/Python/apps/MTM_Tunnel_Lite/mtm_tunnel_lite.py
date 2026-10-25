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

# Embedded canonical HX XXTEA implementation.
import base64
import binascii
import math
import re
import struct
MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
MASK = 0xffffffff
DELTA = (-1638454863) & MASK
LIST_FIELDS = ("Free_servers", "Premium_servers", "Vip_servers", "Private_servers", "Payloads")

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
        raise DecodeError("FORMAT_ERROR", "Se esperaba Base64 estándar del catálogo.")
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
        raise DecodeError("WRONG_DOCUMENT", "El documento debe contener un objeto JSON.")
    return _validate(doc)

def _mx(total, y, z, position, e, key):
    return (((total ^ y) + (key[(position & 3) ^ e] ^ z))
            ^ (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))) & MASK

def decrypt_catalog_bytes(data: bytes | str, *, key: bytes | None = None) -> bytes:
    """Shared APK XXTEA variant; select the current default key at call-time."""
    if key is None:
        key = CATALOG_KEY
    encrypted = _base64(_text(data))
    if len(encrypted) < 8 or len(encrypted) % 4:
        raise DecodeError("TRUNCATED", "El catálogo no contiene palabras XXTEA completas.")
    values = list(struct.unpack("<" + "I" * (len(encrypted) // 4), encrypted))
    key = struct.unpack("<4I", key[:16].ljust(16, b"\0"))
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

def _catalog_json(data) -> dict:
    doc = _json(data)
    if not any(field in doc for field in LIST_FIELDS):
        raise DecodeError("WRONG_DOCUMENT", "No hay listas de servidores o payloads en el catálogo.")
    for field in LIST_FIELDS:
        if field in doc and (not isinstance(doc[field], list) or any(not isinstance(v, dict) for v in doc[field])):
            raise DecodeError("WRONG_DOCUMENT", "Las listas de catálogo deben contener objetos completos.")
    return doc


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
