#!/usr/bin/env python3
"""TRM Tunnel (com.trm.tunnel, versionCode 19, versionName 2.8): catalog decoder, local or explicit HTTPS.

Standalone Python 3.10+, standard library only; no APK needed at runtime.
For .hxt files or encrypted profile text use TRM_Tunnel_archivos.py.
TRM Tunnel has no live custom text/link scheme (see README.md).

Method verified by decompiling this APK (jadx 1.5.3, LSParanoid strings
recovered from the DEX bytecode with the same algorithm as HX Tunnel VPN):
  * Download: OpenVPNClient.z() builds a Volley-style request (EW) for the
    fixed updater URL below and queues it (DP.a); the response listener is
    LLJ.e. EW.f() returns no custom headers and the request method is GET
    (cache key "0:"+url); the transport (HurlStack/HttpURLConnection) sends
    no app headers, so the download is a plain GET. The server answers 200
    to any User-Agent (verified with Dalvik, "TRM Tunnel/2.8" and Mozilla);
    this script sends "Dalvik/2.1.0" + "Accept-Encoding: identity", the
    platform-agent family the app's stack produces.
  * Handler LLJ.e: response.replace(" ", "").replace("\\n", ""), then
    Km.c(response, Km.a) = Base64 -> XXTEA (delta 0x9E5729B1, key "Princie!")
    -> JSON. If "Version" equals the local one: "No Update Available!";
    otherwise local Payloads whose "message" starts with "Custom Tweak" are
    kept, remote Payloads are merged by "friendly_name" (case-insensitive),
    and the merged JSON is re-encrypted with J90.r = Km.e (XXTEA + Base64)
    into filesDir + "/gremlin.json". The bundled asset assets/gremlin.json
    is the same format (version 6.47 at build time).
  * Local read (a.m): filesDir/gremlin.json if present, else the asset,
    decrypted with Km.c. Km is the XXTEA class (LKm; in classes2.dex);
    Km.a is the fixed format key "Princie!", Km.b/Km.d the byte encrypt /
    decrypt cores, Km.c/Km.e the String wrappers (Base64 + XXTEA).
  * The format has no MAC; structural validation is not cryptographic
    authentication.

The server (LiteSpeed) often closes the connection mid-body
("transfer closed with N bytes remaining", cuts at 16 KiB multiples, same
behaviour as APNA Tunnel Lite). This script first tries the plain GET the
app makes (3 attempts) and, only if it does not complete, resumes by
ranges ("Range: bytes=...") with the same headers, validating the result
by Content-Length and by successful decryption. That fallback is a
transport workaround, not part of the app's request.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from http.client import HTTPException, IncompleteRead
import json
import math
import os
from pathlib import Path
import re
import struct
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
MASK = 0xFFFFFFFF
DELTA = (-1638454863) & MASK  # XXTEA variant delta 0x9E5729B1 (LKm).
# Shared format constant in LKm.a, not an account credential.
CATALOG_KEY = b"Princie!"
CATALOG_URL = "https://trmrelay.store/updater/b30b74ddd6a4c221face88bdcd27df"
USER_AGENT = "Dalvik/2.1.0"  # Platform-agent family of the app's HTTP stack.
LIST_FIELDS = ("Free_servers", "Premium_servers", "Vip_servers", "Private_servers", "Payloads")
BUNDLED_ASSET = "assets/gremlin.json"


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
    """LKm.c: Base64 -> XXTEA (last-word length) -> JSON bytes."""
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
    if not any(field in doc for field in LIST_FIELDS):
        raise DecodeError("WRONG_DOCUMENT", "No hay listas de servidores o payloads en el catálogo.")
    for field in LIST_FIELDS:
        if field in doc and (not isinstance(doc[field], list) or any(not isinstance(v, dict) for v in doc[field])):
            raise DecodeError("WRONG_DOCUMENT", "Las listas de catálogo deben contener objetos completos.")
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


def summary(doc: dict) -> dict:
    """Counts only; never reproduces decrypted values."""
    out = {"Version": doc.get("Version")}
    for field in LIST_FIELDS:
        value = doc.get(field)
        out[field] = len(value) if isinstance(value, list) else None
    out["sections"] = sorted(doc.keys())
    return out


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


def _headers(extra=None):
    headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity"}
    if extra:
        headers.update(extra)
    return headers


def _read_response(response, expected=None):
    try:
        data = response.read(MAX_BYTES + 1)
    except IncompleteRead as exc:
        data = exc.partial or b""
        if expected is not None and len(data) >= expected:
            return data[:expected]
        raise _Truncated(data, expected) from exc
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La respuesta supera el límite de tamaño.")
    return data


class _Truncated(Exception):
    def __init__(self, partial: bytes, expected):
        super().__init__("download truncated")
        self.partial = partial
        self.expected = expected


def _get(url, headers, opener):
    req = Request(url, headers=headers, method="GET")
    with opener.open(req, timeout=25) as response:
        if response.status != 200:
            raise DecodeError("DOWNLOAD_FAILED", "El endpoint no devolvió 200.")
        length = response.headers.get("Content-Length")
        expected = int(length) if length and length.isdigit() else None
        data = _read_response(response, expected)
        if expected is not None and len(data) != expected:
            raise _Truncated(data, expected)
        return data, expected


def _fetch_window(url, start, end, expected, opener):
    """Fetch exactly bytes start..end (inclusive), retrying empty/truncated reads.

    The server sometimes answers a Range request with an empty body (the
    connection is closed before any byte arrives); a plain retry of the
    same window is what unblocks it. A 200 that ignores Range is handled
    by slicing the needed window out of the full body.
    """
    want = end - start + 1
    for _ in range(8):
        req = Request(url, headers=_headers({"Range": f"bytes={start}-{end}"}), method="GET")
        try:
            with opener.open(req, timeout=25) as response:
                if response.status == 200:
                    try:
                        body = response.read(MAX_BYTES + 1)
                    except IncompleteRead as exc:
                        body = exc.partial or b""
                    if len(body) >= expected:
                        return body[start:end + 1]
                    continue
                if response.status != 206:
                    raise DecodeError("DOWNLOAD_FAILED", "La reanudación por rangos no devolvió contenido.")
                try:
                    chunk = response.read(MAX_BYTES + 1)
                except IncompleteRead as exc:
                    chunk = exc.partial or b""
                if chunk:
                    return chunk[:want]
        except DecodeError:
            raise
        except (HTTPError, URLError, HTTPException, OSError, ValueError):
            continue
    raise DecodeError("DOWNLOAD_TRUNCATED", "La reanudación por rangos no avanzó.")


def _resume(url, partial, expected, opener):
    """Range resume in 16 KiB blocks; transport fallback only."""
    data = bytearray(partial)
    while len(data) < expected:
        start = len(data)
        end = min(expected, start + 16384) - 1
        data.extend(_fetch_window(url, start, end, expected, opener))
    return bytes(data[:expected])


def fetch_catalog(url: str = CATALOG_URL) -> bytes:
    """Plain GET exactly as the app makes it; range-resume only if truncated."""
    _https_url(url)
    opener = build_opener(_HTTPSRedirect())
    last_truncated = None
    for _ in range(3):
        try:
            data, _expected = _get(url, _headers(), opener)
            return data
        except _Truncated as exc:
            last_truncated = exc
            if exc.expected is not None:
                try:
                    return _resume(url, exc.partial or b"", exc.expected, opener)
                except (DecodeError, HTTPError, URLError, HTTPException, OSError, ValueError):
                    continue
        except (HTTPError, URLError, HTTPException, OSError, ValueError) as exc:
            code = "ACCESS_DENIED" if isinstance(exc, HTTPError) and exc.code in (401, 403) else "DOWNLOAD_FAILED"
            raise DecodeError(code, "No se pudo descargar el catálogo mediante HTTPS.") from exc
    if last_truncated is not None:
        raise DecodeError("DOWNLOAD_TRUNCATED", "La descarga se cortó y no se pudo completar.")
    raise DecodeError("DOWNLOAD_FAILED", "No se pudo descargar el catálogo mediante HTTPS.")


def read_bundled(apk_path: Path) -> bytes:
    """assets/gremlin.json from the APK (same encrypted format as the remote)."""
    try:
        with zipfile.ZipFile(apk_path) as zf:
            return zf.read(BUNDLED_ASSET)
    except (OSError, KeyError, zipfile.BadZipFile) as exc:
        raise DecodeError("APK_ERROR", "No se pudo leer el catálogo incrustado del APK.") from exc


def _read_file(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


def _write_output(path: Path, rendered: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, rendered.encode("utf-8"))
    finally:
        os.close(fd)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path, help="Respuesta del catálogo guardada localmente")
    source.add_argument("--url", nargs="?", const=CATALOG_URL,
                        help="Descarga explícita; por defecto usa el endpoint original")
    source.add_argument("--apks", type=Path, metavar="APK",
                        help="Lee assets/gremlin.json del APK indicado")
    source.add_argument("--stdin", action="store_true", help="Lee la respuesta cifrada desde stdin")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo; no sobrescribe")
    parser.add_argument("--summary", action="store_true",
                        help="Solo recuentos (versión y tamaños de lista), sin valores descifrados")
    args = parser.parse_args(argv)
    try:
        if args.url is not None:
            raw = fetch_catalog(args.url)
        elif args.apks is not None:
            raw = read_bundled(args.apks)
        elif args.stdin:
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
        else:
            raw = _read_file(args.file)
        doc = decode(raw)
        if args.summary:
            rendered = json.dumps(summary(doc), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        else:
            rendered = json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            _write_output(args.output, rendered)
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
