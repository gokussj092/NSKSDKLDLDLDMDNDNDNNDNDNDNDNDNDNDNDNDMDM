#!/usr/bin/env python3
"""MKK Hyper VPN 2.9.2: complete catalogs and subscription downloads.

Standalone Python 3.10+ and PyCryptodome. No APK required at runtime.
For individual mkk:// texts use MKK_Hyper_VPN_textos.py. See README.md.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from concurrent.futures import ThreadPoolExecutor
import hashlib
from http.client import HTTPException
import json
import math
from pathlib import Path
import re
import sys
from threading import Lock
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from Crypto.Cipher import AES

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
MAX_SOURCES = 128
MAX_TOTAL_BYTES = 64 * 1024 * 1024
CATALOG_URL = "https://f005.backblazeb2.com/file/mkkhyper/api_server.json"
SOURCES = {
    "servers": CATALOG_URL,
    "static": "https://flashvpn.sgp1.digitaloceanspaces.com/static.json",
    "subscriptions": "https://f005.backblazeb2.com/file/mkkhyper/subscriptions.json",
    "legacy-subscriptions": "https://raw.githubusercontent.com/Tunzen665/flash-vpn/refs/heads/main/sub.json",
}
USER_AGENT = "MKK Hyper VPN/2.9.2"
PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://", "socks://")
# Shared client format constants: UrlEncryption and SecureConfig field 5.
FORMAT_XOR_KEY = b"invisiVpnSecure2024"
ENCODED_PAYLOAD_SECRET = "LSFOWUI9YDomFDQkQTxRawMLfCM="


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
    return value


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


def _payload_key() -> bytes:
    data = base64.b64decode(ENCODED_PAYLOAD_SECRET)
    secret = bytes(value ^ FORMAT_XOR_KEY[i % len(FORMAT_XOR_KEY)] for i, value in enumerate(data))
    return hashlib.sha256(secret).digest()


def decrypt_catalog_bytes(envelope: dict) -> bytes:
    if not isinstance(envelope.get("nonce"), str) or not isinstance(envelope.get("cipher_text"), str):
        raise DecodeError("FORMAT_ERROR", "Faltan nonce o cipher_text del sobre GCM.")
    nonce, cipher = _base64(envelope["nonce"]), _base64(envelope["cipher_text"])
    tag_value = envelope.get("mac")
    if tag_value is None:
        if len(cipher) <= 16:
            raise DecodeError("TRUNCATED", "Falta el tag GCM adjunto al cifrado.")
        cipher, tag = cipher[:-16], cipher[-16:]
    elif isinstance(tag_value, str):
        tag = _base64(tag_value)
    else:
        raise DecodeError("FORMAT_ERROR", "mac debe ser Base64 o estar ausente.")
    if len(nonce) != 12 or len(tag) != 16:
        raise DecodeError("FORMAT_ERROR", "Se esperaba nonce de 12 bytes y tag de 16 bytes.")
    try:
        return AES.new(_payload_key(), AES.MODE_GCM, nonce=nonce).decrypt_and_verify(cipher, tag)
    except ValueError as exc:
        raise DecodeError("AUTH_FAILED", "La autenticación AES-GCM del catálogo falló.") from exc


def _catalog_document(doc):
    if isinstance(doc, list):
        lists = [doc]  # Legacy server array, preserved without wrapping.
    elif isinstance(doc, dict):
        known = [field for field in ("servers", "static_users", "subscriptions") if field in doc]
        if known:
            lists = [doc[field] for field in known]
        elif doc and all(isinstance(v, str) and v.startswith("https://") for v in doc.values()):
            return doc  # Legacy subscription-name -> URL manifest.
        else:
            raise DecodeError("WRONG_DOCUMENT", "No se identificó un catálogo de servidores o suscripciones.")
    else:
        raise DecodeError("WRONG_DOCUMENT", "El catálogo debe ser un objeto o una lista JSON.")
    if any(not isinstance(values, list) or any(not isinstance(v, dict) for v in values) for values in lists):
        raise DecodeError("WRONG_DOCUMENT", "Las listas de catálogo deben contener objetos completos.")
    return doc


def _subscription_text(text: str) -> dict:
    profiles = [line.strip() for line in re.split(r"[\r\n]+", text) if line.strip().startswith(PROTOCOLS)]
    if not profiles:
        raise DecodeError("WRONG_DOCUMENT", "La respuesta no contiene URI VPN de suscripción.")
    return {"raw_text": text, "profiles": profiles}


def decode(data: bytes | str):
    """Offline: full GCM/legacy JSON, or full subscription text with URI list."""
    original = _text(data)
    text = original.strip()
    if text.startswith(("{", "[")):
        doc = _json(text)
        if isinstance(doc, dict) and any(k in doc for k in ("nonce", "cipher_text", "mac")):
            plain = decrypt_catalog_bytes(doc)
            try:
                clear = plain.decode("utf-8")
            except UnicodeError as exc:
                raise DecodeError("INVALID_JSON", "El catálogo claro no es UTF-8 válido.") from exc
            doc = _json(clear)
        return _catalog_document(doc)
    if not any(line.strip().startswith(PROTOCOLS) for line in text.splitlines()):
        try:
            text = _base64(text).decode("utf-8")
        except UnicodeError as exc:
            raise DecodeError("FORMAT_ERROR", "La suscripción no contiene UTF-8 válido.") from exc
    else:
        text = original
    return _validate(_subscription_text(text))


def run(file_bytes: bytes | str) -> str | None:
    """Offline API. Never downloads or converts errors into empty lists."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


def _https_url(url: str):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment):
        raise ValueError("invalid HTTPS URL")
    return parsed


class _HTTPSRedirect(HTTPRedirectHandler):
    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            _https_url(newurl)
        except ValueError:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_catalog(url: str = CATALOG_URL) -> bytes:
    try:
        _https_url(url)
        req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json, text/plain"}, method="GET")
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


def expand_subscriptions(doc, *, allow_partial: bool = False) -> dict:
    """Explicit network operation. Preserve manifest entries and each response."""
    if isinstance(doc, dict) and isinstance(doc.get("subscriptions"), list):
        urls = [entry.get("url") for entry in doc["subscriptions"]]
    elif isinstance(doc, dict) and doc and all(isinstance(v, str) for v in doc.values()):
        urls = list(doc.values())
    else:
        raise DecodeError("WRONG_DOCUMENT", "--expand requiere un índice de suscripciones.")
    if len(urls) > MAX_SOURCES:
        raise DecodeError("SIZE_LIMIT", "El índice supera el límite de fuentes.")
    try:
        for url in urls:
            if not isinstance(url, str):
                raise ValueError("missing URL")
            _https_url(url)
    except ValueError as exc:
        raise DecodeError("FORMAT_ERROR", "El índice debe contener URL HTTPS completas.") from exc

    total, lock = 0, Lock()

    def download(item):
        nonlocal total
        index, url = item
        try:
            raw = fetch_catalog(url)
        except DecodeError as exc:
            return {"index": index, "status": "error", "error": exc.code}
        with lock:
            total += len(raw)
            if total > MAX_TOTAL_BYTES:
                raise DecodeError("SIZE_LIMIT", "Las respuestas combinadas superan el límite de tamaño.")
        try:
            return {"index": index, "status": "ok", "data": decode(raw)}
        except DecodeError as exc:
            return {"index": index, "status": "error", "error": exc.code}

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(download, enumerate(urls)))
    complete = all(item["status"] == "ok" for item in results)
    if not complete and not allow_partial:
        raise DecodeError("INCOMPLETE_CATALOG", "Fallaron fuentes del índice; use --allow-partial para obtener un informe explícito.")
    return _validate({"catalog": doc, "complete": complete, "sources": results})


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
    source.add_argument("--url", nargs="?", const="", help="Descarga explícita; por defecto usa el endpoint original")
    parser.add_argument("--source", choices=SOURCES, default="servers", help="Fuente original para --url sin argumento")
    parser.add_argument("--expand", action="store_true", help="Descargar las URL del índice de suscripciones")
    parser.add_argument("--allow-partial", action="store_true", help="Con --expand, informar fuentes fallidas sin ocultarlas")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo; por defecto stdout")
    args = parser.parse_args(argv)
    if args.allow_partial and not args.expand:
        parser.error("--allow-partial requiere --expand")
    try:
        url = args.url or SOURCES[args.source]
        result = decode(fetch_catalog(url) if args.url is not None else _read(args.file))
        if args.expand:
            result = expand_subscriptions(result, allow_partial=args.allow_partial)
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
