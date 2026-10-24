#!/usr/bin/env python3
"""ANY VPN 16kb-page-size (40): lector y descargador para Python/Termux."""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import sys
from urllib.request import HTTPRedirectHandler, Request, build_opener

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

MAX_BYTES = 8 * 1024 * 1024
KEY = hashlib.sha256(b"red1987").digest()  # UtilsKey.key, fixed build constant.
CATALOG_URL = "https://free-panel.myprotectionservices.com/uploads/json/1e760370dff563b8fa00.json"
USER_AGENT = "okhttp/5.0.0-alpha.12"  # Default in the APK's bundled OkHttp.
SERVER_FIELDS = frozenset({"ServerIPHost", "ServerCloudFrontHost", "ServerHTTPHost",
    "ServerUser", "ServerPass", "vaddress", "vhost", "etServerAddress", "etEndpoint",
    "etPublicKey", "etPrivateKey", "etPreSharedKey", "etAllowedIPs"})
NETWORK_FIELDS = frozenset({"Payload", "Squid", "SNIHost", "vsni"})
METADATA_FIELDS = frozenset({"config_url", "account_api"})


class DecodeError(ValueError):
    pass


def bounded(data):
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError("Entrada vacía o superior a 8 MiB.")
    return data


def render(value):
    return json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)


def unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise DecodeError("JSON con claves duplicadas.")
        obj[key] = value
    return obj


def constant(_):
    raise DecodeError("JSON con números no finitos.")


def validate(value):
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > 64 or nodes > 200000:
            raise DecodeError("Documento superior a los límites JSON.")
        if isinstance(item, dict):
            for key in item:
                key.encode("utf-8")
            pending.extend((v, depth+1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth+1) for v in item)
        elif isinstance(item, str):
            item.encode("utf-8")
        elif isinstance(item, float) and not math.isfinite(item):
            raise DecodeError("JSON con números no finitos.")


def parse(text):
    obj = json.loads(text, object_pairs_hook=unique, parse_constant=constant)
    validate(obj)
    if not isinstance(obj, dict):
        raise DecodeError("Se esperaba un objeto JSON.")
    return obj


def open_text(value):
    if not isinstance(value, str):
        raise DecodeError("Tipo de campo cifrado inválido.")
    compact = "".join(value.split()).encode("ascii")
    if not compact or len(compact) > MAX_BYTES or len(compact) % 4 == 1:
        raise DecodeError("Base64 inválido.")
    raw = base64.b64decode(compact + b"=" * (-len(compact) % 4), validate=True)
    if not raw or len(raw) % 16:
        raise DecodeError("Sobre AES-CBC inválido.")
    return unpad(AES.new(KEY, AES.MODE_CBC, bytes(16)).decrypt(raw), 16).decode("utf-8")


def open_document(data):
    text = bounded(data).decode("utf-8-sig").strip()
    # Servers.js is stored as JSON after the official updater opens the envelope.
    return parse(text if text.startswith("{") else open_text(text))


def open_fields(item, fields):
    if not isinstance(item, dict):
        raise DecodeError("Perfil inválido.")
    result = item.copy()
    for key in fields & item.keys():
        value = item[key]
        if not isinstance(value, str):
            raise DecodeError("Tipo de campo cifrado inválido.")
        result[key] = "" if value == "" else open_text(value)
    return result


def decode_catalog(data):
    try:
        obj = open_document(data)
        if not isinstance(obj.get("Version"), str) or not obj["Version"]:
            raise DecodeError("Versión de catálogo inválida.")
        for name, fields in (("Servers", SERVER_FIELDS), ("Networks", NETWORK_FIELDS)):
            rows = obj.get(name)
            if not isinstance(rows, list) or not rows:
                raise DecodeError("Lista de catálogo inválida.")
            if any(not isinstance(v, dict) or not isinstance(v.get("Name"), str) for v in rows):
                raise DecodeError("Perfil de catálogo inválido.")
            obj[name] = [open_fields(v, fields) for v in rows]
        obj = open_fields(obj, METADATA_FIELDS)
        validate(obj)
        return obj
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise DecodeError("Catálogo inválido o incompatible con ANY VPN build 40.") from exc


def decode_profile(data):
    try:
        obj = open_document(data)
        sections = [name for name in ("server", "network") if name in obj and obj[name] != ""]
        if not sections:
            raise DecodeError("El archivo no contiene perfiles.")
        for name in sections:
            value = obj[name]
            # Official .dtk stores a complete JSON object inside each string.
            if isinstance(value, str):
                value = parse(value)
            if not isinstance(value, dict) or not isinstance(value.get("Name"), str):
                raise DecodeError("Sección de perfil inválida.")
            obj[name] = open_fields(value, SERVER_FIELDS if name == "server" else NETWORK_FIELDS)
        validate(obj)
        return obj
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise DecodeError("Archivo inválido o incompatible con ANY VPN .dtk.") from exc


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DecodeError("La fuente fija intentó redirigir la descarga.")


def download():
    request = Request(CATALOG_URL, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"})
    try:
        with build_opener(NoRedirect()).open(request, timeout=25) as response:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise DecodeError("Respuesta remota inválida.")
            return bounded(response.read(MAX_BYTES+1))
    except OSError as exc:
        raise DecodeError("No se pudo descargar el catálogo oficial de ANY VPN.") from exc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--file", type=Path, help="Descifrar una exportación .dtk")
    source.add_argument("--catalog", type=Path, help="Abrir una copia de catálogo")
    parser.add_argument("-o", "--output", type=Path, default=Path("any_vpn_resultado.json"))
    args = parser.parse_args()
    try:
        path = args.file or args.catalog
        if path:
            with path.open("rb") as stream:
                data = bounded(stream.read(MAX_BYTES+1))
        else:
            data = download()
        obj = decode_profile(data) if args.file else decode_catalog(data)
        result = (render(obj)+"\n").encode("utf-8")
        with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
            stream.write(result)
        print(f"Guardado: {args.output}")
        if not args.file:
            print(f"Versión {obj['Version']}: {len(obj['Servers'])} servidores / {len(obj['Networks'])} redes")
        return 0
    except (ValueError, OSError) as exc:
        print(str(exc) if isinstance(exc, DecodeError) else "No se pudo leer o guardar; utiliza un destino nuevo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
