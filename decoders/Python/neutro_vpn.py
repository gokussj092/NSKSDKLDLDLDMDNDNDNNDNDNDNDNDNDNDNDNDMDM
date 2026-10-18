#!/usr/bin/env python3
"""Neutro Vpn 1.5: .nvpnc profiles, signed catalogs and standard VPN links.

Standalone Python 3.10+ / PyCryptodome. Only --url/download_catalog() use
the network. Password-protected NVPNC1.P files need their original password.
See docs/NEUTRO_VPN_1_5.md for formats, evidence and limits.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import hashlib
from http.client import HTTPException
import json
import math
from pathlib import Path
import re
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import uuid

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
MAX_PASSWORD_BYTES = 16384
PBKDF2_ROUNDS = 120000
BUILD_CODE = 6
USER_AGENT = "NeutroVpn/1"
CATALOG_URLS = (
    "https://neutro-config.hemdrova.workers.dev/c",
    "https://raw.githubusercontent.com/DKARLTECH/notes/main/c.txt",
)
# Shared client format constants, not account credentials or a signing key.
SHARED_KEY = base64.b64decode("3NyRmmrnhIr23hMCPDGJriYyGBUEAjGoPFX8PwU8qsY=")
CATALOG_PUBLIC_KEY = base64.b64decode(
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJd+lPAWWDx7ixJBromgwN8YzeSR43fMds"
    "I5Wk2S0yzP7Fg6kmppnFZMQF/YxRhxhOebiHN2xgAdAYz0Soa9LAw=="
)
LINK_SCHEMES = {"vless", "vmess", "trojan", "ss", "hysteria", "hysteria2", "hy2"}


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


def _base64(text: str, *, urlsafe: bool = False) -> bytes:
    compact = re.sub(r"[ \t\r\n]", "", text)
    pattern = r"[A-Za-z0-9+/_-]+={0,2}" if urlsafe else r"[A-Za-z0-9+/]+={0,2}"
    if not re.fullmatch(pattern, compact) or len(compact) % 4 == 1:
        raise DecodeError("FORMAT_ERROR", "Base64 inválido.")
    try:
        return base64.b64decode(compact + "=" * (-len(compact) % 4),
                                altchars=b"-_" if urlsafe else None, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DecodeError("FORMAT_ERROR", "Base64 inválido.") from exc


def _unique(pairs):
    doc = {}
    for key, value in pairs:
        if key in doc:
            raise ValueError("duplicate key")
        doc[key] = value
    return doc


def _nonfinite(_value):
    raise ValueError("nonfinite number")


def _validate(doc: Any) -> Any:
    pending, count = [(doc, 0)], 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if depth > MAX_DEPTH or count > MAX_NODES:
            raise DecodeError("SIZE_LIMIT", "El JSON supera los límites de complejidad.")
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


def _json(data: bytes | str) -> dict:
    try:
        value = json.loads(data, object_pairs_hook=_unique, parse_constant=_nonfinite)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("INVALID_JSON", "JSON inválido o con claves duplicadas.") from exc
    if not isinstance(value, dict):
        raise DecodeError("WRONG_DOCUMENT", "Se esperaba un objeto JSON.")
    return _validate(value)


def _decrypt(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
    if len(nonce) != 12 or len(ciphertext) < 17:
        raise DecodeError("TRUNCATED", "Nonce o contenido AES-GCM incompleto.")
    try:
        return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
    except (ValueError, TypeError) as exc:
        raise DecodeError("AUTH_FAILED", "La contraseña, la clave o la autenticación GCM no son válidas.") from exc


def decode_profile(data: bytes | str, *, password: str | None = None) -> dict:
    """Read NVPNC1.L/P without applying Android's import policies or defaults."""
    parts = _text(data).split(".")
    if len(parts) != 5 or parts[0] != "NVPNC1" or parts[1] not in ("L", "P"):
        raise DecodeError("FORMAT_ERROR", "Se esperaba un perfil NVPNC1.L o NVPNC1.P.")
    mode = parts[1]
    salt = _base64(parts[2]) if parts[2] else b""
    nonce, ciphertext = _base64(parts[3]), _base64(parts[4])
    if (mode == "L" and salt) or (mode == "P" and len(salt) != 16):
        raise DecodeError("FORMAT_ERROR", "Longitud de salt distinta a la del exportador analizado.")
    key = SHARED_KEY
    if mode == "P":
        if not isinstance(password, str) or not password:
            raise DecodeError("PASSWORD_REQUIRED", "Se necesita la contraseña original de este perfil.")
        try:
            encoded = password.encode("utf-8")
        except UnicodeError as exc:
            raise DecodeError("FORMAT_ERROR", "La contraseña no es UTF-8 válido.") from exc
        if len(encoded) > MAX_PASSWORD_BYTES:
            raise DecodeError("SIZE_LIMIT", "Contraseña demasiado larga.")
        key = hashlib.pbkdf2_hmac("sha256", encoded, salt, PBKDF2_ROUNDS, 32)
    return _json(_decrypt(ciphertext, nonce, key))


def decode_catalog(data: bytes | str, *, public_key: bytes | None = None) -> dict:
    """Verify ECDSA before AES-GCM; retain the entire remote configuration."""
    parts = _text(data).split(".")
    if len(parts) != 3:
        raise DecodeError("FORMAT_ERROR", "Se esperaba nonce.ciphertext.firma.")
    nonce, ciphertext, signature = map(_base64, parts)
    if len(nonce) != 12 or len(ciphertext) < 17:
        raise DecodeError("TRUNCATED", "Catálogo incompleto.")
    try:
        key = ECC.import_key(CATALOG_PUBLIC_KEY if public_key is None else public_key)
        if key.has_private():
            raise ValueError("public key required")
        DSS.new(key, "fips-186-3", encoding="der").verify(SHA256.new(nonce + ciphertext), signature)
    except (ValueError, TypeError, IndexError) as exc:
        raise DecodeError("SIGNATURE_INVALID", "La firma del catálogo no es válida para esta aplicación.") from exc
    doc = _json(_decrypt(ciphertext, nonce, SHARED_KEY))
    if "profiles" in doc and (not isinstance(doc["profiles"], list)
                              or any(not isinstance(p, dict) for p in doc["profiles"])):
        raise DecodeError("WRONG_DOCUMENT", "profiles debe contener una lista de objetos completa.")
    return doc


def decode_link(data: bytes | str) -> dict:
    """Inspect standard URI/Base64 fields; do not generate an Xray runtime config."""
    text = _text(data)
    if re.search(r"[\x00-\x20\x7f]", text) or "://" not in text:
        raise DecodeError("FORMAT_ERROR", "Se esperaba un solo enlace VPN.")
    scheme, rest = text.split("://", 1)
    scheme = scheme.lower()
    if scheme not in LINK_SCHEMES:
        raise DecodeError("FORMAT_ERROR", "Tipo de enlace no identificado en esta versión.")
    body, _, fragment = rest.partition("#")
    main, _, query = body.partition("?")
    try:
        fragment = unquote(fragment, errors="strict")
        result = {"type": "link", "scheme": scheme, "raw": text, "fragment": fragment}
        if scheme == "vmess" and "@" not in main:
            result["config"] = _json(_base64(main, urlsafe=True))
        else:
            if scheme == "ss" and "@" not in main:
                main = _base64(main.rstrip("/"), urlsafe=True).decode("utf-8")
            parsed = urlsplit(scheme + "://" + main)
            if not parsed.hostname or parsed.port == 0:
                raise ValueError("missing server")
            userinfo = main.rsplit("@", 1)[0] if "@" in main else ""
            if scheme == "ss":
                try:
                    candidate = _base64(userinfo, urlsafe=True).decode("utf-8")
                    userinfo = candidate if ":" in candidate else unquote(userinfo, errors="strict")
                except (DecodeError, UnicodeError):
                    userinfo = unquote(userinfo, errors="strict")
                if ":" not in userinfo:
                    raise ValueError("missing shadowsocks method")
                result["method"], result["password"] = userinfo.split(":", 1)
            else:
                userinfo = unquote(userinfo, errors="strict")
            result.update({"server": parsed.hostname, "port": parsed.port, "userinfo": userinfo, "path": parsed.path})
        result["query"] = [[unquote(p.partition("=")[0], errors="strict"),
                            unquote(p.partition("=")[2], errors="strict")]
                           for p in query.split("&") if p]
        return _validate(result)
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, DecodeError):
            raise
        raise DecodeError("FORMAT_ERROR", "El enlace contiene campos inválidos.") from exc


def decode(data: bytes | str, *, password: str | None = None) -> dict:
    text = _text(data)
    if text.startswith("NVPNC"):
        return decode_profile(text, password=password)
    if "://" in text.split("\n", 1)[0] and not text.startswith("{"):
        return decode_link(text)
    if text.startswith("{"):
        doc = _json(text)
        if not isinstance(doc.get("outbounds"), list) or not doc["outbounds"]:
            raise DecodeError("WRONG_DOCUMENT", "El JSON Xray debe incluir outbounds.")
        return doc
    return decode_catalog(text)


def run(file_bytes: bytes | str, *, password: str | None = None) -> str | None:
    try:
        return json.dumps(decode(file_bytes, password=password), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


class _HTTPSRedirect(HTTPRedirectHandler):
    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlsplit(newurl)
        if parsed.scheme != "https" or parsed.username is not None or parsed.password is not None:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _download(url: str, install_id: str) -> bytes:
    try:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ValueError("invalid HTTPS URL")
        target = url + ("&" if parsed.query else "?") + urlencode({"i": install_id, "b": BUILD_CODE})
        req = Request(target, headers={"User-Agent": USER_AGENT}, method="GET")
        with build_opener(_HTTPSRedirect()).open(req, timeout=20) as response:
            if response.status != 200:
                raise OSError("unexpected status")
            data = response.read(MAX_BYTES + 1)
    except HTTPError as exc:
        code = "ACCESS_DENIED" if exc.code in (401, 403) else "DOWNLOAD_FAILED"
        raise DecodeError(code, "El endpoint no devolvió un catálogo accesible.") from exc
    except (OSError, ValueError, URLError, HTTPException) as exc:
        raise DecodeError("DOWNLOAD_FAILED", "No se pudo descargar el catálogo mediante HTTPS.") from exc
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La respuesta supera el límite de tamaño.")
    return data


def download_catalog(url: str | None = None) -> dict:
    """First authenticated endpoint, or explicit URL only; never use the APK cache."""
    install_id = uuid.uuid4().hex
    urls = CATALOG_URLS if url is None else (url,)
    for index, endpoint in enumerate(urls):
        try:
            return decode_catalog(_download(endpoint, install_id))
        except DecodeError:
            if index == len(urls) - 1:
                raise
    raise DecodeError("DOWNLOAD_FAILED", "No hay endpoints configurados.")


def _read(path: Path, limit: int) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path, help=".nvpnc, respuesta de catálogo o texto guardado")
    source.add_argument("--text", help="Perfil NVPNC1, enlace estándar o JSON Xray")
    source.add_argument("--url", nargs="?", const="", help="Descarga explícita; sin valor usa los endpoints originales")
    auth = parser.add_mutually_exclusive_group()
    auth.add_argument("--ask-password", action="store_true", help="Pedir la contraseña original sin mostrarla")
    auth.add_argument("--password-file", type=Path, help="Contraseña UTF-8, retira solo un LF/CRLF final")
    parser.add_argument("-o", "--output", type=Path, help="JSON completo; por defecto stdout")
    args = parser.parse_args(argv)
    if args.url is not None and (args.ask_password or args.password_file):
        parser.error("La contraseña se aplica a perfiles locales, no al catálogo.")
    try:
        password = None
        if args.password_file:
            password = _read(args.password_file, MAX_PASSWORD_BYTES + 2).decode("utf-8")
            if password.endswith("\n"):
                password = password[:-1].removesuffix("\r")
        elif args.ask_password:
            password = getpass.getpass("Contraseña original: ")
        result = download_catalog(args.url or None) if args.url is not None else decode(
            args.text if args.text is not None else _read(args.file, MAX_BYTES), password=password)
        rendered = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        return 0
    except DecodeError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    except (UnicodeError, EOFError):
        print(json.dumps({"error": "FORMAT_ERROR", "message": "No se pudo leer la contraseña UTF-8."}), file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR", "message": "No se pudo leer o escribir el archivo."}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
