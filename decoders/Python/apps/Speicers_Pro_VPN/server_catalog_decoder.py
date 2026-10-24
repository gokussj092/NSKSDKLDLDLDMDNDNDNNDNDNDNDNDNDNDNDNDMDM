#!/usr/bin/env python3
"""Speicers`Pro VPN 104.1.17 (120): descarga privada para Python/Termux."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import unicodedata
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

MAX_BYTES = 8 * 1024 * 1024
CATALOG_URL = "https://raw.githubusercontent.com/satanas66666/Aplicaciones/refs/heads/main/speicerspro/servidores_pro"
# Build constants from LICENSE and the DEX, not downloaded account credentials.
CATALOG_PASSWORD = b"ProteccionSanta$666"
FIELD_KEY = b"Diablo2310BAX9t".ljust(32, b"\0")
GLYPH_PASSWORD = "公鸡快乐$3210VcF".encode("utf-8")
ALPHABET = "▙▚▛▜▝▞▟▃▄▅▆▇█▉▊▐"
FIELD_NAMES = {
    "Payload": "PFFSWRJKZmOcNLTZxFwgjQ==", "ProxyIp": "SbDP19AbQur0YtkkyRlVMA==",
    "ProxyPort": "vXfVafVdyaCRTDj6uBT6lg==", "SNI": "tmSbWiCK1hvytJ9f3gflkQ==",
    "ServerIP": "U7V8DoP4cYkXJjCnpqW6nQ==", "ServerPass": "Fo3TT4oONvv69IQIMg1aLg==",
    "ServerPort": "p9ZPlMv9V7gDszRoUaNaJw==", "ServerUser": "mtw364P3ZslP2CZYuHTCHQ==",
    "V2rayAddress": "oAqgFKE3WywLRvSvKffLOA==", "V2rayHost": "BWTPMwR0iRu1N9twHCpbAg==",
    "V2rayPort": "b6stZNVaFUjLCw88dn03Ng==", "sFlag": "ACqWMY4zuZWzSEs8cZMXIw==",
    "sInfo": "66P9ZUEM1ju4WGhv856BSg==", "sName": "p0PgL3l0d89mnssz7ImPJA==",
    "udpObfs": "iW1aO5DgThVAeo23xTsXSw==", "udpauth": "b3MPypEFR83rzFKUa4UbCw==",
    "udpbuffer": "asmRO4zXsRjhDYX42dbNuw==", "udpdown": "MkRXl4D9vpREVCJ0w4qrgg==",
    "udpport": "2kDKELRmSE143VdcX3FPzw==", "udpserver": "ITkWvEHp29BmMaLMEGUFcw==",
    "udpup": "B5jcTSGuJUFbTtH5O1IaBg==", "v2rayJson": "W4CbS1nMWo6Y2noeUFHmXQ==",
    "v2rayid": "EtNSBhechjWxm2t50NyB9Q==", "v2raypath": "aH2nzD4eDLxPSxIAlVivdg==",
}


class DecodeError(ValueError):
    """Errors never include catalog contents or remote response bodies."""


def bounded(data):
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError("Entrada vacía o superior a 8 MiB.")
    return data


def _base64(value, *, urlsafe=False):
    clean = "".join(value.split()).encode("ascii")
    if not clean or len(clean) % 4 == 1:
        raise DecodeError("Base64 inválido.")
    if urlsafe:
        clean = clean.translate(bytes.maketrans(b"-_", b"+/"))
    return base64.b64decode(clean + b"=" * (-len(clean) % 4), validate=True)


def rotate_java(text):
    # Java operates on UTF-16 char units. Supplementary letters stay unchanged.
    raw = text.encode("utf-16-le")
    chars = []
    for offset in range(0, len(raw), 2):
        c = chr(int.from_bytes(raw[offset:offset+2], "little"))
        if unicodedata.category(c).startswith("L"):
            c = chr((ord(c) - (42 if c.isupper() else 74)) % 26 + (65 if c.isupper() else 97))
        chars.append(ord(c).to_bytes(2, "little"))
    return b"".join(chars).decode("utf-16-le")


def decode_field(value):
    if not isinstance(value, str):
        raise DecodeError("Tipo de campo cifrado inválido.")
    if value == "":
        return value
    raw = _base64(value, urlsafe=True)
    if len(raw) < 32 or len(raw) % 16:
        raise DecodeError("Campo AES-CBC inválido.")
    text = unpad(AES.new(FIELD_KEY, AES.MODE_CBC, raw[:16]).decrypt(raw[16:]), 16).decode("utf-8")
    return rotate_java(text)


def _unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise DecodeError("JSON con claves duplicadas.")
        obj[key] = value
    return obj


def _constant(_):
    raise DecodeError("JSON con números no finitos.")


def _validate(obj):
    pending = [(obj, 0)]
    nodes = 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if depth > 64 or nodes > 200000:
            raise DecodeError("Documento superior a los límites JSON.")
        if isinstance(value, dict):
            for key in value:
                key.encode("utf-8")
            pending.extend((v, depth+1) for v in value.values())
        elif isinstance(value, list):
            pending.extend((v, depth+1) for v in value)
        elif isinstance(value, str):
            value.encode("utf-8")
        elif isinstance(value, float) and not math.isfinite(value):
            raise DecodeError("JSON con números no finitos.")


def decrypt_document(data):
    text = bounded(data).decode("utf-8-sig").strip()
    if text and text[0] in ALPHABET:
        if len(text) % 2 or any(c not in ALPHABET for c in text):
            raise DecodeError("Alfabeto de catálogo inválido.")
        packed = bytes(ALPHABET.index(text[i]) * 16 + ALPHABET.index(text[i+1]) for i in range(0, len(text), 2))
        raw = _base64(packed.decode("ascii"))
        key = hashlib.sha256(GLYPH_PASSWORD.hex().upper().encode("ascii")).digest()
        iv = bytes(16)
    else:
        packed = _base64(text)
        if len(packed) < 32 or packed[:8] != b"WakkoDev":
            raise DecodeError("Encabezado de catálogo incompatible.")
        material = previous = b""
        while len(material) < 48:
            previous = hashlib.md5(previous + CATALOG_PASSWORD + packed[8:16]).digest()
            material += previous
        key, iv, raw = material[:32], material[32:48], packed[16:]
    if not raw or len(raw) % 16:
        raise DecodeError("Sobre AES-CBC inválido.")
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(raw), 16).decode("utf-8")


def decode_catalog(data):
    try:
        obj = json.loads(decrypt_document(data), object_pairs_hook=_unique, parse_constant=_constant)
        _validate(obj)
        if not isinstance(obj, dict):
            raise DecodeError("Catálogo incompatible.")
        if "Servers" in obj:
            if not isinstance(obj.get("Version"), str) or not obj["Version"]:
                raise DecodeError("Versión de catálogo inválida.")
            records = obj["Servers"]
            if not isinstance(records, list) or not records:
                raise DecodeError("Lista de servidores inválida.")
            for item in records:
                if not isinstance(item, dict) or not isinstance(item.get(FIELD_NAMES["sName"]), str):
                    raise DecodeError("Perfil de servidor inválido.")
                # Keep all entries, opaque keys, unknown fields and enablement flags.
                for key in FIELD_NAMES.values():
                    if key in item:
                        item[key] = decode_field(item[key])
        elif "servers" in obj:
            # Secondary bundled config/config.json contains plaintext inner fields.
            if (not isinstance(obj.get("version"), str) or not obj["version"] or
                    not isinstance(obj["servers"], list) or not obj["servers"] or
                    any(not isinstance(v, dict) or not isinstance(v.get("serverName"), str) for v in obj["servers"])):
                raise DecodeError("Catálogo secundario incompatible.")
        else:
            raise DecodeError("El documento no contiene servidores.")
        _validate(obj)
        return obj
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        raise DecodeError("Catálogo inválido o incompatible con Speicers Pro 104.1.17.") from exc


def render(obj):
    return json.dumps(obj, ensure_ascii=False, indent=2, allow_nan=False)


def run(data: bytes) -> str:
    """Offline worker entry point; never downloads data."""
    return render(decode_catalog(data))


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DecodeError("La fuente fija intentó redirigir la descarga.")


def download():
    request = Request(CATALOG_URL, headers={"Accept-Encoding": "identity"})
    try:
        with build_opener(_NoRedirect()).open(request, timeout=25) as response:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise DecodeError("Respuesta remota inválida.")
            return bounded(response.read(MAX_BYTES + 1))
    except OSError as exc:
        raise DecodeError("No se pudo descargar el catálogo oficial.") from exc


def _read(path):
    with path.open("rb") as stream:
        return bounded(stream.read(MAX_BYTES + 1))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--input", type=Path, help="Descifrar una copia cifrada local")
    source.add_argument("--apk", type=Path, help="Leer un catálogo incluido en base.apk")
    parser.add_argument("--asset", choices=["flags/config.png", "config/config.json"], default="flags/config.png")
    parser.add_argument("-o", "--output", type=Path, default=Path("speicers_pro_catalogo.json"), help="Archivo JSON nuevo; nunca sobrescribe")
    args = parser.parse_args()
    try:
        if args.input:
            data = _read(args.input)
        elif args.apk:
            with zipfile.ZipFile(args.apk) as archive:
                with archive.open("assets/" + args.asset) as stream:
                    data = bounded(stream.read(MAX_BYTES + 1))
        else:
            data = download()
        obj = decode_catalog(data)
        rendered = (render(obj) + "\n").encode("utf-8")
        with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
            stream.write(rendered)
        records = obj.get("Servers", obj.get("servers", []))
        print(f"Guardado: {args.output} | versión {obj.get('Version', obj.get('version'))} | {len(records)} servidores")
        return 0
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
        print(str(exc) if isinstance(exc, DecodeError) else "No se pudo leer o guardar; el destino debe ser un archivo nuevo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
