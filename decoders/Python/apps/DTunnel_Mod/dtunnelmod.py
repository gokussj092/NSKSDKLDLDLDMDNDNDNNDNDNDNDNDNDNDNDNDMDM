#!/usr/bin/env python3
"""DTunnel Mod 4.2.5: encrypted catalogs and vpn:// JSON links.

Requires PyCryptodome. Network access occurs only with explicit --url or
fetch_catalog(). APK account identifiers are supplied by the caller, never
embedded. See docs/DTUNNELMOD_4_2_5.md for evidence and validation limits.
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
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

MAX_BYTES = 32 * 1024 * 1024
MAX_NODES = 1_000_000
MAX_DEPTH = 64
CATALOG_URL = "https://dtmod.cloud/api/dtunnelmod"
USER_AGENT = "DTunnelMod (@DTunnelMod, @DTunnelModGroup, @LightXVD)"
# Shared client format constant, NOT credentials.json.user_id or token.
CATALOG_SEED = b"DTunnelModSecret-API-9c69a0b72b442ccac3e6aaaa7630d12f2b351fe395e9fe667efa0907cde90da5"
CATALOG_KEY = hashlib.sha256(CATALOG_SEED).digest()
UPDATE_KINDS = {"catalog": "app_config", "layout": "app_layout", "texts": "app_text"}


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _text(data: bytes | str) -> str:
    if not isinstance(data, (bytes, str)):
        raise DecodeError("FORMAT_ERROR", "La entrada debe ser bytes o texto UTF-8.")
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    try:
        text = data.decode("utf-8-sig") if isinstance(data, bytes) else data.removeprefix("\ufeff")
        if len(text.encode("utf-8")) > MAX_BYTES:
            raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    except UnicodeError as exc:
        raise DecodeError("FORMAT_ERROR", "La entrada no es UTF-8 válido.") from exc
    return text.strip()


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


def _validate(doc: Any) -> Any:
    pending = [(doc, 0)]
    count = 0
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
            raise DecodeError("INVALID_JSON", "El JSON contiene un número no finito.")
        elif isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeError as exc:
                raise DecodeError("INVALID_JSON", "El JSON contiene Unicode inválido.") from exc
    return doc


def _json(text: str) -> Any:
    try:
        doc = json.loads(text, object_pairs_hook=_unique, parse_constant=_nonfinite)
    except (ValueError, RecursionError) as exc:
        raise DecodeError("INVALID_JSON", "JSON inválido o con claves duplicadas.") from exc
    return _validate(doc)


def decrypt_catalog_text(data: bytes | str) -> str:
    """Return UTF-8 plaintext; padding/JSON checks do not authenticate CBC."""
    encrypted = _base64(_text(data))
    if not encrypted or len(encrypted) % AES.block_size:
        raise DecodeError("TRUNCATED", "El catálogo no contiene bloques AES completos.")
    try:
        plain = unpad(AES.new(CATALOG_KEY, AES.MODE_CBC, bytes(16)).decrypt(encrypted), 16)
        return plain.decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("DECRYPT_FAILED", "No se pudo descifrar el catálogo con este formato.") from exc


def decode_catalog(data: bytes | str, *, kind: str = "catalog") -> list[dict]:
    """Decode every catalog member, preserving unknown fields and ordering."""
    if kind not in UPDATE_KINDS:
        raise DecodeError("FORMAT_ERROR", "Tipo de actualización desconocido.")
    doc = _json(decrypt_catalog_text(data))
    if not isinstance(doc, list):
        raise DecodeError("WRONG_DOCUMENT", "La respuesta debe contener una lista JSON.")
    result = []
    for member in doc:
        item = _json(member) if isinstance(member, str) else member
        if not isinstance(item, dict):
            raise DecodeError("WRONG_DOCUMENT", "Cada miembro debe ser un objeto o su cadena JSON.")
        result.append(item)
    return _validate(result)


def decode_link(data: bytes | str) -> dict:
    """Decode vpn://Base64(UTF-8 JSON); retain original IDs and fields."""
    text = _text(data)
    if not text.startswith("vpn://"):
        raise DecodeError("FORMAT_ERROR", "Se esperaba un enlace vpn://.")
    try:
        plain = _base64(text[6:]).decode("utf-8")
    except UnicodeError as exc:
        raise DecodeError("FORMAT_ERROR", "El enlace no contiene UTF-8 válido.") from exc
    doc = _json(plain)
    if not isinstance(doc, dict):
        raise DecodeError("WRONG_DOCUMENT", "El enlace debe contener un objeto JSON.")
    return doc


def decode(data: bytes | str, *, kind: str = "catalog") -> list[dict] | dict:
    text = _text(data)
    return decode_link(text) if text.startswith("vpn://") else decode_catalog(text, kind=kind)


def run(file_bytes: bytes | str, *, kind: str = "catalog") -> str | None:
    """Offline repository contract: complete JSON string or None on failure."""
    try:
        return json.dumps(decode(file_bytes, kind=kind), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_catalog(url: str, request_id: str, *, kind: str = "catalog") -> bytes:
    """Explicit GET with caller-supplied identifier; no redirects or retries."""
    if not isinstance(request_id, str) or not re.fullmatch(r"[\x21-\x7e]{1,512}", request_id):
        raise DecodeError("CREDENTIALS_REQUIRED", "Se necesita un identificador válido sin espacios ni saltos de línea.")
    if kind not in UPDATE_KINDS:
        raise DecodeError("FORMAT_ERROR", "Tipo de actualización desconocido.")
    try:
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname or parts.username is not None or parts.password is not None or parts.fragment:
            raise ValueError("invalid URL")
        request = Request(url, headers={"User-Agent": USER_AGENT,
                          "dtunnel-token": request_id, "dtunnel-update": UPDATE_KINDS[kind]}, method="GET")
        with build_opener(_NoRedirect()).open(request, timeout=20) as response:
            data = response.read(MAX_BYTES + 1)
    except HTTPError as exc:
        if exc.code in (401, 403):
            raise DecodeError("ACCESS_DENIED", "El servicio rechazó el identificador de acceso.") from exc
        raise DecodeError("DOWNLOAD_FAILED", "El servicio no devolvió una respuesta válida; no se siguen redirecciones.") from exc
    except (OSError, ValueError, URLError, HTTPException) as exc:
        raise DecodeError("DOWNLOAD_FAILED", "No se pudo descargar el catálogo mediante HTTPS.") from exc
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La respuesta supera el límite de tamaño.")
    return data


def _read(path: Path, limit: int) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path, help="Respuesta cifrada o enlace guardado en texto")
    source.add_argument("--link", help="Enlace vpn:// completo")
    source.add_argument("--url", nargs="?", const=CATALOG_URL, help="Descarga explícita; por defecto el endpoint del APK")
    parser.add_argument("--kind", choices=UPDATE_KINDS, default="catalog", help="catalog: servidores; layout/texts: interfaz")
    auth = parser.add_mutually_exclusive_group()
    auth.add_argument("--credentials-file", type=Path, help="credentials.json original; usa user_id para la actualización normal")
    auth.add_argument("--request-id-file", type=Path, help="Identificador explícito UTF-8 para dtunnel-token")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo; por defecto stdout")
    args = parser.parse_args(argv)
    if (args.credentials_file or args.request_id_file) and args.url is None:
        parser.error("Los identificadores se usan solamente con --url.")
    try:
        if args.url is not None:
            if args.credentials_file:
                credentials = _json(_text(_read(args.credentials_file, 16384)))
                request_id = credentials.get("user_id") if isinstance(credentials, dict) else None
            elif args.request_id_file:
                request_id = _read(args.request_id_file, 514).decode("utf-8").removesuffix("\n").removesuffix("\r")
            else:
                raise DecodeError("CREDENTIALS_REQUIRED", "Use --credentials-file o --request-id-file para descargar.")
            result = decode_catalog(fetch_catalog(args.url, request_id, kind=args.kind), kind=args.kind)
        elif args.link is not None:
            result = decode_link(args.link)
        else:
            result = decode(_read(args.file, MAX_BYTES), kind=args.kind)
        rendered = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        return 0
    except DecodeError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    except UnicodeError:
        print(json.dumps({"error": "FORMAT_ERROR", "message": "El identificador no es UTF-8 válido."}), file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR", "message": "No se pudo leer o escribir el archivo."}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
