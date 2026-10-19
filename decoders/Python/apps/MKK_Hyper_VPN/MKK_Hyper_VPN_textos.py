#!/usr/bin/env python3
"""MKK Hyper VPN 2.9.2: mkk:// text reader, including saved text files.

Standalone Python 3.10+ and PyCryptodome. No network or APK required.
No proprietary file extension was identified. See README.md.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import math
from pathlib import Path
import re
import sys
from urllib.parse import parse_qsl, unquote, urlsplit

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
# Shared format material in MkkKeyHelper._aesKey, not a user credential.
KEY_MATERIAL = b"MKKHyperVPN_2025_SecureKey_v1.0!"
PROTOCOLS = ("vless", "vmess", "trojan", "ss", "socks")


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
    if not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", compact) or len(compact) % 4 == 1:
        raise DecodeError("FORMAT_ERROR", "Se esperaba Base64 válido.")
    try:
        return base64.b64decode(compact + "=" * (-len(compact) % 4), altchars=b"-_", validate=True)
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
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        doc = json.loads(data, object_pairs_hook=_unique, parse_constant=_nonfinite)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("INVALID_JSON", "JSON inválido o con claves duplicadas.") from exc
    return _validate(doc)


def decrypt_key(data: bytes | str) -> str:
    text = _text(data)
    if not text.startswith("mkk://"):
        raise DecodeError("FORMAT_ERROR", "Se esperaba una clave mkk://.")
    raw = _base64(text[6:])
    if len(raw) < 32 or (len(raw) - 16) % 16:
        raise DecodeError("TRUNCATED", "Se esperaba IV de 16 bytes y bloques AES completos.")
    key = KEY_MATERIAL[:32].ljust(32, b"\0")
    try:
        plain = AES.new(key, AES.MODE_CBC, iv=raw[:16]).decrypt(raw[16:])
        return unpad(plain, 16).decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("DECRYPT_FAILED", "No se pudo descifrar la clave mkk://.") from exc


def inspect_uri(uri: str) -> dict:
    # Preserve the exact URI; this is inspection, not an executable Xray config.
    protocol = uri.partition("://")[0]
    if protocol not in PROTOCOLS or not uri.startswith(protocol + "://"):
        raise DecodeError("WRONG_DOCUMENT", "La clave no contiene un protocolo VPN identificado.")
    result = {"protocol": protocol, "uri": uri}
    if protocol == "vmess":
        config = _json(_base64(uri[8:]))
        if not isinstance(config, dict):
            raise DecodeError("WRONG_DOCUMENT", "VMess debe contener un objeto JSON.")
        result["config"] = config
    else:
        try:
            parsed = urlsplit(uri)
            # Ordered pairs retain repeated and blank parameters; URI stays exact.
            result["details"] = {"authority": parsed.netloc, "path": unquote(parsed.path),
                                 "query": [list(pair) for pair in parse_qsl(parsed.query, keep_blank_values=True)],
                                 "name": unquote(parsed.fragment)}
        except ValueError as exc:
            raise DecodeError("WRONG_DOCUMENT", "URI VPN inválida.") from exc
    return _validate(result)


def decode(data: bytes | str) -> dict:
    text = _text(data)
    clear = decrypt_key(text) if text.startswith("mkk://") else text
    return inspect_uri(clear)


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
    source.add_argument("file", nargs="?", type=Path, help="Archivo de texto con una clave mkk:// o URI VPN")
    source.add_argument("--text", help="Clave mkk:// o URI VPN pegada")
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
