#!/usr/bin/env python3
"""24clan VPN Green 3.3: catalog decoder only, local or explicit HTTPS.

Python 3.10+ and PyCryptodome. See README.md in this directory.
For .green files or pasted profile text use 24clan_VPN_Green_archivos.py.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
from http.client import HTTPException
import json
import math
from pathlib import Path
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
CATALOG_URL = "https://24clanvpn.com/updater/6d5d4a5fb3d053300c1a89f85dbf05"
USER_AGENT = "24clan VPN Green/3.3"
# Shared OpenSSL format passphrase from g9.g, not an account credential.
CATALOG_PASSPHRASE = b"mtscrypt"
LIST_FIELDS = ("Servers", "PremiumServers", "Tweaks", "PremiumTweaks")


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
        raise DecodeError("FORMAT_ERROR", "Se esperaba Base64 estándar.")
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
        raise DecodeError("WRONG_DOCUMENT", "El catálogo debe contener un objeto JSON.")
    return _validate(doc)


def decrypt_catalog_text(data: bytes | str) -> str:
    text = _text(data)
    if text.startswith("{"):
        return text  # g9.g returns plaintext unchanged if OpenSSL cannot decode it.
    raw = _base64(text)
    if not raw.startswith(b"Salted__"):
        raise DecodeError("FORMAT_ERROR", "Se esperaba el contenedor OpenSSL Salted__ del catálogo.")
    if len(raw) < 32 or (len(raw) - 16) % 16:
        raise DecodeError("TRUNCATED", "El catálogo contiene bloques AES incompletos.")
    salt = raw[8:16]
    material, previous = b"", b""
    while len(material) < 48:
        previous = hashlib.md5(previous + CATALOG_PASSPHRASE + salt).digest()
        material += previous
    try:
        plain = AES.new(material[:32], AES.MODE_CBC, material[32:48]).decrypt(raw[16:])
        return unpad(plain, 16).decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("DECRYPT_FAILED", "No se pudo descifrar este catálogo.") from exc


def decode(data: bytes | str) -> dict:
    doc = _json(decrypt_catalog_text(data))
    if not any(field in doc for field in LIST_FIELDS):
        raise DecodeError("WRONG_DOCUMENT", "No hay listas de servidores o tweaks en el catálogo.")
    for field in LIST_FIELDS:
        if field in doc and (not isinstance(doc[field], list) or any(not isinstance(v, dict) for v in doc[field])):
            raise DecodeError("WRONG_DOCUMENT", "Las listas de catálogo deben contener objetos completos.")
    return doc


def run(file_bytes: bytes | str) -> str | None:
    """Offline API: complete catalog JSON or None; never a partial list."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


class _HTTPSRedirect(HTTPRedirectHandler):
    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlsplit(newurl)
        if parsed.scheme != "https" or parsed.username is not None or parsed.password is not None:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_catalog(url: str = CATALOG_URL) -> bytes:
    try:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ValueError("invalid HTTPS URL")
        req = Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
        with build_opener(_HTTPSRedirect()).open(req, timeout=20) as response:
            if response.status != 200:
                raise OSError("unexpected HTTP status")
            data = response.read(MAX_BYTES + 1)
    except HTTPError as exc:
        code = "ACCESS_DENIED" if exc.code in (401, 403) else "DOWNLOAD_FAILED"
        raise DecodeError(code, "El endpoint no devolvió un catálogo accesible.") from exc
    except (OSError, ValueError, URLError, HTTPException) as exc:
        raise DecodeError("DOWNLOAD_FAILED", "No se pudo descargar el catálogo mediante HTTPS.") from exc
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La respuesta supera el límite de tamaño.")
    return data


def _read(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path, help="Respuesta del catálogo guardada localmente")
    source.add_argument("--url", nargs="?", const=CATALOG_URL, help="Descarga explícita; por defecto usa el endpoint original")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo; por defecto stdout")
    args = parser.parse_args(argv)
    try:
        result = decode(fetch_catalog(args.url) if args.url is not None else _read(args.file))
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
