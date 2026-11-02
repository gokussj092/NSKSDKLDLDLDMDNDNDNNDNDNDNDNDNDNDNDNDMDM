#!/usr/bin/env python3
"""Speicers`Pro VPN 104.1.17/104.1.20 (120/123): descarga privada para Python/Termux."""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import math
import os
import re
from pathlib import Path
import sys
import unicodedata
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

MAX_BYTES = 8 * 1024 * 1024
CATALOG_URL = "https://raw.githubusercontent.com/satanas66666/Aplicaciones/refs/heads/main/speicerspro/servidores_pro"
UPDATE_ORIGIN = "https://gen.spei.click"
UPDATE_MANIFEST_URL = UPDATE_ORIGIN + "/updates/servers.json"
SPCF_KEY_ID = "a8d4e7d79e33bcb8"
SPCF_PUBLIC_KEY = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA3AjjZkkCkznJzdy9YO7fPQUCaE7FrWnQeazmI7uMt6CrPL4XwXIYQDu+WSAKyQUkfCRrDnWBDYZac4cHjqxnYLyu/gaFvjIu6VAqq/GwZ3RzK586ST+AIH4nT++BnHQOzh9uciEhUM6xuZfGh2XJm+51WCytP0tijSKglw37O+WIK6+fwbvtS1UJYLsDSmfbzRFO8wX3iD5H65XouYC7sl2YfYz7IKFYnI6wzz3R6JbobGg8g52T31kR1cPmDc7rHZuz2btOrV44Nmm5UmpA78oGdtfTiIzEBSNXBOuP/AbCpu7J/Xly75FfjG2HSUBFS3OoMkvYoIT1rkLndahMJEsTJPXlxyehZZXGWYTy8uYlmnjCCdMLKuxLdKjs/STpDuHF2U41DR/r90cRwNZ2gkRquahG0VO8XLR1VrUUosdN5iETOXjA3Yhgd4zzIgy2bx29Dg2cPhs0zrqYyecQGvfONeKYflVRQajyUNXpPsw9mLQRJc6I2OjVtsTrcLt1AgMBAAE="
SPCF_HMAC_KEY = bytes.fromhex("15960080267cfa3877dce327aa0cfbbaadf8dc4ff47a3cad680e865bdbc18000")
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


def _json(text):
    value = json.loads(text, object_pairs_hook=_unique, parse_constant=_constant)
    _validate(value)
    return value


def _url64(text):
    if not isinstance(text, str) or not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", text):
        raise DecodeError("Base64 URL inválido.")
    raw = _base64(text, urlsafe=True)
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != text.rstrip("="):
        raise DecodeError("Base64 URL no canónico.")
    return raw


def _signed(value, max_payload):
    if (not isinstance(value, dict) or value.get("alg") != "RS256"
            or not isinstance(value.get("payload"), str)
            or not re.fullmatch(r"[A-Za-z0-9_-]+", value["payload"])
            or len(value["payload"]) > max_payload):
        raise DecodeError("Sobre firmado incompatible.")
    signature = _url64(value.get("signature"))
    pkcs1_15.new(RSA.import_key(base64.b64decode(SPCF_PUBLIC_KEY))).verify(
        SHA256.new(value["payload"].encode("ascii")), signature)
    payload = _json(_url64(value["payload"]).decode("utf-8"))
    if not isinstance(payload, dict) or payload.get("app") != "netfree.mx.store":
        raise DecodeError("Publicación de otra aplicación.")
    return payload


def decrypt_spcf(text):
    if not text.startswith("SPCF1\n") or len(text) > 3_000_000:
        raise DecodeError("Archivo SPCF1 incompatible.")
    obj = _signed(_json(text[6:]), 3_000_000)
    expected = {"v": 1, "kind": "servers_file", "format": "SPCF1",
                "kdf": "PBKDF2-HMAC-SHA256", "iterations": 600000, "key_id": SPCF_KEY_ID}
    if any(type(obj.get(k)) is not type(v) or obj[k] != v for k, v in expected.items()):
        raise DecodeError("Parámetros SPCF1 incompatibles.")
    salt, nonce, ciphertext = (_url64(obj.get(k)) for k in ("salt", "nonce", "ciphertext"))
    if len(salt) != 32 or len(nonce) != 12 or not 16 <= len(ciphertext) <= 1_500_016:
        raise DecodeError("Archivo SPCF1 incompleto.")
    password = base64.urlsafe_b64encode(hmac.new(SPCF_HMAC_KEY,
        b"SPEICERS_FILE_PASSWORD_V1\0" + CATALOG_PASSWORD, "sha256").digest()).rstrip(b"=")
    key = hashlib.pbkdf2_hmac("sha256", password, salt, 600000, 32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update((f"SPCF1|netfree.mx.store|servers|{SPCF_KEY_ID}|600000|{obj['salt']}").encode("ascii"))
    plain = cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:]).decode("utf-8")
    document = _json(plain)
    if not isinstance(document, dict) or not isinstance(document.get("Servers"), list) or len(document["Servers"]) > 10000:
        raise DecodeError("Lista SPCF1 incompatible.")
    return plain


def update_manifest(data):
    if not isinstance(data, bytes) or not 0 < len(data) <= 16000:
        raise DecodeError("Publicación superior al límite.")
    obj = _signed(_json(data.decode("utf-8")), 800000)
    expected = {"v": 1, "kind": "server_update", "origin": UPDATE_ORIGIN, "format": "SPCF1", "min_app_code": 121}
    if any(type(obj.get(k)) is not type(v) or obj[k] != v for k, v in expected.items()):
        raise DecodeError("Publicación no compatible.")
    version, digest = obj.get("version"), obj.get("sha256")
    if (not isinstance(version, str) or not re.fullmatch(r"[1-9][0-9]{0,9}", version)
            or int(version) > 2147483647 or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or type(obj.get("size")) is not int or not 1 <= obj["size"] <= 3_000_000
            or type(obj.get("count")) is not int or not 0 <= obj["count"] <= 10000):
        raise DecodeError("Publicación incompleta.")
    if obj.get("url") != f"{UPDATE_ORIGIN}/updates/servers/{version}/{digest}.png":
        raise DecodeError("Ruta de actualización no permitida.")
    return obj


def decrypt_document(data):
    text = bounded(data).decode("utf-8-sig").strip()
    if text.startswith("SPCF1"):
        return decrypt_spcf(text)
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
        raise DecodeError("Catálogo inválido o incompatible con Speicers Pro 120/123.") from exc


def render(obj):
    return json.dumps(obj, ensure_ascii=False, indent=2, allow_nan=False)


def run(data: bytes) -> str:
    """Offline worker entry point; never downloads data."""
    return render(decode_catalog(data))


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DecodeError("La fuente fija intentó redirigir la descarga.")


def download_legacy():
    request = Request(CATALOG_URL, headers={"Accept-Encoding": "identity"})
    try:
        with build_opener(_NoRedirect()).open(request, timeout=25) as response:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise DecodeError("Respuesta remota inválida.")
            return bounded(response.read(MAX_BYTES + 1))
    except OSError as exc:
        raise DecodeError("No se pudo descargar el catálogo oficial.") from exc


def _request_update(url, limit, accept):
    request = Request(url, headers={"Cache-Control": "no-cache", "Accept": accept,
                                   "User-Agent": "Dalvik/2.1.0", "Accept-Encoding": "identity"})
    try:
        with build_opener(_NoRedirect()).open(request, timeout=20) as response:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise DecodeError("Respuesta de actualización inválida.")
            data = response.read(limit + 1)
    except OSError as exc:
        raise DecodeError("No se pudo descargar la actualización oficial.") from exc
    if not 0 < len(data) <= limit:
        raise DecodeError("Actualización superior al límite.")
    return data


def download():
    # Both URLs are fixed by the original signed publication, never caller input.
    manifest = update_manifest(_request_update(UPDATE_MANIFEST_URL, 16000, "application/json"))
    data = _request_update(manifest["url"], 3_000_000, "application/octet-stream")
    if len(data) != manifest["size"] or hashlib.sha256(data).hexdigest() != manifest["sha256"]:
        raise DecodeError("Actualización incompleta o alterada.")
    if not data.startswith(b"SPCF1\n"):
        raise DecodeError("Actualización sin protección SPCF1.")
    document = decode_catalog(data)
    if document.get("Version") != manifest["version"] or len(document.get("Servers", [])) != manifest["count"]:
        raise DecodeError("La lista no coincide con la publicación firmada.")
    return data


def _read(path):
    with path.open("rb") as stream:
        return bounded(stream.read(MAX_BYTES + 1))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--legacy-remote", action="store_true", help="GET histórico del build120; no sustituye el feed SPCF1 actual")
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
            data = download_legacy() if args.legacy_remote else download()
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
