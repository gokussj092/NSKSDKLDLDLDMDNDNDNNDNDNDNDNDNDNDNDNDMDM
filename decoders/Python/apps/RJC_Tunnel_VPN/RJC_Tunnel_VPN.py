#!/usr/bin/env python3
"""RJC Tunnel VPN RJC-19: catalog decoder, local or explicit HTTPS.

Standalone Python 3.10+, standard library only; no APK needed at runtime.
Package com.rjctunnel.vpn, versionCode 19, versionName RJC-19.

Catalog source recovered from OpenVPNClient.z() (Volley request NW) and the
response callback HJ.e(), with the XXTEA codec in AbstractC0333Mm:
GET https://raw.githubusercontent.com/pipoyrichards/RJCTUNNEL/refs/heads/main/FEBRUARY
The app sends no custom headers: the repackaged HTTP stack (C3797ow) issues a
plain GET with User-Agent "datatransport/3.3.0 android/", no body, no auth,
connect/read timeout 2500 ms, caches disabled. The response callback strips
spaces and newlines, then decrypts Base64 -> XXTEA (delta 0x9e5729b1) -> JSON,
checks that the remote Version is newer than the local one (OpenVPNClient.w),
merges locally saved "Custom Tweak" payloads into Payloads, and stores the
result re-encrypted (same XXTEA key) as filesDir/gremlin.json. The bundled
asset gremlin.json and the stored local copy use the identical encoding, so
this decoder also opens both.

Same XXTEA recipe and format key as RJC TUNNEL PRO RJC-6 (com.rjct.pro) and
Mx Tunnel PRO; only the catalog endpoint differs (RJCTUNNEL vs RJCPRO repo).
"""
from __future__ import annotations

import argparse
import base64
import binascii
from http.client import HTTPException
import json
import math
from pathlib import Path
import re
import struct
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
MASK = 0xffffffff
DELTA = (-1638454863) & MASK  # APK XXTEA variant: 0x9e5729b1.
# Shared format constant in AbstractC0333Mm.a, not an account credential.
CATALOG_KEY = b"...|..."
CATALOG_URL = "https://raw.githubusercontent.com/pipoyrichards/RJCTUNNEL/refs/heads/main/FEBRUARY"
# Exact User-Agent the app's HTTP stack (C3797ow) sends; no other headers.
USER_AGENT = "datatransport/3.3.0 android/"
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
    # The app strips spaces and newlines before decoding (HJ.e).
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
    if not isinstance(doc.get("Version"), str) or not doc["Version"]:
        raise DecodeError("WRONG_DOCUMENT", "El catálogo no trae una Version válida.")
    if any(not isinstance(doc.get(k), list) for k in LIST_FIELDS):
        raise DecodeError("WRONG_DOCUMENT", "Faltan listas de servidores o payloads en el catálogo.")
    if not any(doc[k] for k in LIST_FIELDS):
        raise DecodeError("WRONG_DOCUMENT", "El catálogo no trae servidores ni payloads.")
    return doc


def decode(data: bytes | str) -> dict:
    """Offline API: decrypt the complete catalog without merging local profiles."""
    return _catalog_json(decrypt_catalog_bytes(data))


def run(file_bytes: bytes | str) -> str | None:
    """Offline API: complete catalog JSON or None; never a partial list."""
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
    """GET exactly as the app does: no auth, no extra headers, app User-Agent."""
    try:
        _https_url(url)
        req = Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
        with build_opener(_HTTPSRedirect()).open(req, timeout=25) as response:
            if response.status != 200:
                raise OSError("unexpected HTTP status")
            if response.headers.get("Content-Encoding", "identity") != "identity":
                raise DecodeError("DOWNLOAD_FAILED", "Respuesta remota con codificación no esperada.")
            data = response.read(MAX_BYTES + 1)
    except HTTPError as exc:
        code = "ACCESS_DENIED" if exc.code in (401, 403) else "DOWNLOAD_FAILED"
        raise DecodeError(code, "El endpoint no devolvió un catálogo accesible.") from exc
    except (OSError, ValueError, URLError, HTTPException) as exc:
        raise DecodeError("DOWNLOAD_FAILED", "No se pudo descargar el catálogo mediante HTTPS.") from exc
    if not data or len(data) > MAX_BYTES or data.lstrip().startswith(b"<"):
        raise DecodeError("DOWNLOAD_FAILED", "Catálogo vacío, incompatible o superior a 8 MiB.")
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
    source.add_argument("file", nargs="?", type=Path, help="Respuesta del catálogo guardada localmente (también acepta el asset gremlin.json)")
    source.add_argument("--url", nargs="?", const=CATALOG_URL, help="Descarga explícita; por defecto usa el endpoint original")
    source.add_argument("--stdin", action="store_true", help="Leer la respuesta cifrada desde stdin")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo; por defecto stdout")
    args = parser.parse_args(argv)
    try:
        if args.url is not None:
            raw = fetch_catalog(args.url)
        elif args.stdin:
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            raw = _read(args.file)
        result = decode(raw)
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
