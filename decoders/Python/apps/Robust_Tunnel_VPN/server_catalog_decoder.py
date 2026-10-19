#!/usr/bin/env python3
"""Robust Tunnel VPN isvsoft 16.4.7: fixed remote catalog and local copies.

Python 3.10+, standard library only. No APK, account, device ID or VPN login.
run(data) is offline; only the CLI without a file downloads the fixed catalog.
"""
from __future__ import annotations

import argparse
import base64
import json
import math
from pathlib import Path
import re
import struct
import sys
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 64
DELTA = 0x9E130714
MASK = 0xFFFFFFFF
# Shared wire-format material from XEz4WHn / libisvsoftpro.so, not user secrets.
CATALOG_KEY = b"f4Zy8Xx6Lk4U"
FIELD_KEY = b"26ec7fa7d83a6bf8"
CATALOG_URL = "https://xkingvpn.xyz/api/files/app?json=beae113e6e46d674a068"
ENCRYPTED_FIELDS = frozenset({
    "DefUsername", "DefPassword", "xUsername", "xPassword", "xObfs",
    "ServerIP", "ServerWS", "ServerHTTP", "ServerCF", "ServerSSH", "ServerUDPH",
    "ServerKey", "NameServerHost", "V2rayID", "V2rayConf", "V2rayHost",
    "FrontQuery", "BackQuery", "SNIHostname", "HTTPPayload", "SSLPayload",
    "DirectPayload", "OpenVPNHeader", "ProxyIP", "ProxyPort", "UDPConf",
})


class DecodeError(ValueError):
    """Error messages never contain input, remote bodies or credentials."""


def _base64(value: str) -> bytes:
    try:
        compact = "".join(value.split()).encode("ascii")
        if not compact or len(compact) % 4 == 1:
            raise ValueError
        return base64.b64decode(compact + b"=" * (-len(compact) % 4), validate=True)
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("Base64 inválido.") from exc


def _mx(total: int, y: int, z: int, position: int, e: int, key) -> int:
    return ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^
            ((total ^ y) + (key[(position & 3) ^ e] ^ z))) & MASK


def decrypt_xxtea(data: bytes, key: bytes) -> bytes:
    """Original utils.c variant: LE words, custom delta and length trailer."""
    if not data:
        return b""
    if len(data) < 8 or len(data) % 4:
        raise DecodeError("Bloques XXTEA incompletos.")
    words = list(struct.unpack("<%dI" % (len(data) // 4), data))
    key_words = struct.unpack("<4I", key[:16].ljust(16, b"\0"))
    rounds = 6 + 52 // len(words)
    total = (rounds * DELTA) & MASK
    y = words[0]
    for _ in range(rounds):
        e = (total >> 2) & 3
        for position in range(len(words) - 1, 0, -1):
            z = words[position - 1]
            words[position] = (words[position] - _mx(total, y, z, position, e, key_words)) & MASK
            y = words[position]
        z = words[-1]
        words[0] = (words[0] - _mx(total, y, z, 0, e, key_words)) & MASK
        y = words[0]
        total = (total - DELTA) & MASK
    size = words[-1]
    if not len(data) - 7 <= size <= len(data) - 4:
        raise DecodeError("Longitud XXTEA inválida; contenido no compatible.")
    return struct.pack("<%dI" % len(words), *words)[:size]


def decrypt_field(value: str) -> str:
    if value == "":
        return ""
    try:
        if len(value) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", value):
            raise ValueError
        encoded = bytes.fromhex(value).decode("ascii")
        return decrypt_xxtea(_base64(encoded), FIELD_KEY).decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("No se pudo descifrar un campo del catálogo.") from exc


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DecodeError("JSON con claves duplicadas.")
        result[key] = value
    return result


def _reject_constant(_value):
    raise DecodeError("Número JSON no finito.")


def _walk(value, depth=0):
    if depth > MAX_DEPTH:
        raise DecodeError("Profundidad JSON superior a 64.")
    if isinstance(value, list):
        return [_walk(item, depth + 1) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            key.encode("utf-8")
            if key in ENCRYPTED_FIELDS and item is not None:
                if not isinstance(item, str):
                    raise DecodeError("Un campo cifrado no contiene texto.")
                result[key] = decrypt_field(item)
            else:
                result[key] = _walk(item, depth + 1)
        return result
    if isinstance(value, float) and not math.isfinite(value):
        raise DecodeError("Número fuera del rango JSON.")
    if isinstance(value, str):
        value.encode("utf-8")
    return value


def decode(data: bytes) -> dict:
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError("Entrada vacía o superior a 8 MiB.")
    try:
        text = data.decode("utf-8-sig").strip()
        if "://" in text:
            raise DecodeError("Se esperaba un catálogo cifrado, no una URL.")
        plain = decrypt_xxtea(_base64(text), CATALOG_KEY).decode("utf-8")
        obj = json.loads(plain, object_pairs_hook=_unique, parse_constant=_reject_constant)
        if not isinstance(obj, dict):
            raise DecodeError("El catálogo debe contener un objeto JSON.")
        version = obj.get("ConfigVersion")
        if (isinstance(version, bool) or not isinstance(version, (str, int, float)) or
                version == "" or any(not isinstance(obj.get(k), list) for k in ("Servers", "Tweaks")) or
                not (obj["Servers"] or obj["Tweaks"])):
            raise DecodeError("Estructura de catálogo incompatible.")
        for section, name in (("Servers", "ServerName"), ("Tweaks", "TweakName")):
            if any(not isinstance(item, dict) or not isinstance(item.get(name), str) for item in obj[section]):
                raise DecodeError("Elemento de catálogo incompatible.")
        if "Certs" in obj and (not isinstance(obj["Certs"], list) or
                              any(not isinstance(item, dict) for item in obj["Certs"])):
            raise DecodeError("Colección de certificados inválida.")
        return _walk(obj)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("Formato de catálogo inválido o no compatible.") from exc


def run(data: bytes) -> str:
    """Offline Cloud entry point: preserve the entire JSON and its value types."""
    result = json.dumps(decode(data), ensure_ascii=False, indent=2, allow_nan=False)
    if len(result.encode("utf-8")) > MAX_BYTES:
        raise DecodeError("La salida supera 8 MiB.")
    return result


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DecodeError("El proveedor intentó redirigir la descarga.")


def download() -> bytes:
    request = Request(CATALOG_URL, headers={
        "User-Agent": "Robust Tunnel VPN/isvsoft 16.4.7", "Accept-Encoding": "identity",
    })
    try:
        with build_opener(_NoRedirect()).open(request, timeout=25) as response:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise DecodeError("Respuesta remota inválida.")
            data = response.read(MAX_BYTES + 1)
    except OSError as exc:
        raise DecodeError("No se pudo descargar el catálogo autorizado.") from exc
    if not data or len(data) > MAX_BYTES:
        raise DecodeError("Catálogo vacío o superior a 8 MiB.")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument("file", nargs="?", type=Path, help="Copia cifrada local del catálogo, sin extensión obligatoria")
    inputs.add_argument("--stdin", action="store_true", help="Leer una copia cifrada desde stdin")
    args = parser.parse_args()
    try:
        if args.file:
            with args.file.open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
        elif args.stdin:
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            data = download()
        print(run(data))
        return 0
    except (OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, DecodeError) else "No se pudo leer el catálogo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
