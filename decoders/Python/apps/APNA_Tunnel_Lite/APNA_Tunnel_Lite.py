#!/usr/bin/env python3
"""APNA Tunnel Lite (com.apnatunnel.lite, versionCode 51): catálogo, solo biblioteca estándar.

run() is offline; only the explicit CLI/download path accesses the fixed source.
Neither modified XXTEA nor the profile format authenticates ciphertext.

Método verificado decompilando el APK Lite v51 (jadx 1.5.3 sobre classes.dex
+ deofuscación LSParanoid recuperada del bytecode; la clase OpenVPNClient vive
en el DEX secundario protegido por LIAPP, assets/.bxdtcxfzx.dex, que jadx no
pudo cargar, pero el flujo completo está confirmado por las clases visibles):
  * La app guarda el catálogo en filesDir + "/janur.json" y lo lee desde ahí o
    desde el asset assets/janur.json si aún no existe el archivo local.
  * Al actualizar, el handler (RunnableC0962bh, case 2) quita espacios y
    saltos de línea de la respuesta, aplica Base64 estándar y XXTEA modificado
    (AbstractC0030An.c con la clave fija AbstractC0030An.a), compara
    "Version" con la local y, si es mayor, fusiona los "Payloads" locales
    cuyos friendly_name empiecen por "Custom Tweak" y reescribe janur.json
    cifrado (AbstractC2353p30.b = XXTEA + Base64).
  * La URL activa es la constante de la clase Ng (paperonboard.com/updater/…),
    la misma familia que en APNA VPN 3.9; el "UpdaterLink" incluido dentro del
    catálogo (amtun.xyz/updater/…) NO es la llamada del actualizador.
  * La descarga es un GET sin cabeceras propias: Volley no añade
    autenticación, token ni firma. El servidor responde 403 a un User-Agent
    genérico de Python y 200 con User-Agent "Dalvik/2.1.0" y
    "Accept-Encoding: identity", igual que en 3.9.

Catálogo: Base64 -> XXTEA modificado, delta 0x9E5729B1, clave fija
b"...|..." rellenada con ceros a 16 bytes, palabras little-endian de 32 bits
y tamaño original en la última palabra. Idéntico a APNA VPN 3.9; solo cambian
la URL, el nombre del asset (janur.json en vez de janu.json) y la versión.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import http.client
import io
import json
import math
import os
from pathlib import Path
import re
import struct
import sys
import time
import zipfile
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_INPUT = 8 * 1024 * 1024
MAX_BUNDLE = 100 * 1024 * 1024
DELTA = 0x9E5729B1  # APNA modified XXTEA delta (AbstractC0030An.b: -1638454863)
KEY = b"...|..."  # Fixed catalog-format constant (AbstractC0030An.a).
CATALOG_URL = "https://paperonboard.com/updater/6aa1acd5d8b2b25e6884eae4483e57"
USER_AGENT = "Dalvik/2.1.0"  # Reproduces the HttpURLConnection platform agent family.
MASK = 0xFFFFFFFF
ROOT_KEYS = ("Free_servers", "Payloads")
DEFAULT_OUTPUT = "apna_tunnel_lite_catalogo.json"


class CatalogError(ValueError):
    """Invalid or unsupported APNA Tunnel Lite catalog."""


def _unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise CatalogError("Duplicate JSON key")
        obj[key] = value
    return obj


def _constant(_):
    raise CatalogError("Nonfinite JSON number")


def parse_document(text):
    obj = json.loads(text, object_pairs_hook=_unique, parse_constant=_constant)
    if not isinstance(obj, dict):
        raise CatalogError("Expected JSON object")
    pending = [(obj, 0)]
    nodes = 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if depth > 64 or nodes > 200000:
            raise CatalogError("JSON structure exceeds limits")
        if isinstance(value, dict):
            for key in value:
                key.encode("utf-8")
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
        elif isinstance(value, str):
            value.encode("utf-8")
        elif isinstance(value, float) and not math.isfinite(value):
            raise CatalogError("Nonfinite JSON number")
    return obj


def _words(raw: bytes) -> list[int]:
    if not raw:
        return []
    padded = raw.ljust((len(raw) + 3) // 4 * 4, b"\0")
    return list(struct.unpack("<" + "I" * (len(padded) // 4), padded))


def _mx(total: int, y: int, z: int, index: int, e: int, key: list[int]) -> int:
    return (
        (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
        ^ ((total ^ y) + (key[(index & 3) ^ e] ^ z))
    ) & MASK


def decrypt_binary(ciphertext: bytes) -> bytes:
    """Decrypt APNA's little-endian XXTEA envelope with last-word length."""
    if len(ciphertext) < 8 or len(ciphertext) % 4 or len(ciphertext) > MAX_INPUT:
        raise CatalogError("Invalid XXTEA length")
    values = _words(ciphertext)
    key = _words(KEY.ljust(16, b"\0"))
    if len(key) != 4 or len(values) < 2:
        raise CatalogError("Invalid XXTEA key/input")
    end = len(values) - 1
    total = ((6 + 52 // len(values)) * DELTA) & MASK
    y = values[0]
    while total:
        e = (total >> 2) & 3
        for index in range(end, 0, -1):
            z = values[index - 1]
            values[index] = (values[index] - _mx(total, y, z, index, e, key)) & MASK
            y = values[index]
        z = values[end]
        values[0] = (values[0] - _mx(total, y, z, 0, e, key)) & MASK
        y = values[0]
        total = (total - DELTA) & MASK
    output_size = (len(values) - 1) * 4
    plain_size = values[-1]
    if not output_size - 3 <= plain_size <= output_size:
        raise CatalogError("Invalid plaintext length or format variant")
    return struct.pack("<" + "I" * len(values), *values)[:plain_size]


def decode_json_bytes(data: bytes) -> bytes:
    """Return the complete, original UTF-8 JSON bytes without field filtering."""
    if not isinstance(data, bytes) or not data or len(data) > MAX_INPUT:
        raise CatalogError("Invalid input size")
    try:
        normalized = re.sub(rb"\s+", b"", data)
        if not normalized or len(normalized) > MAX_INPUT:
            raise CatalogError("Invalid Base64 input length")
        ciphertext = base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CatalogError("Invalid Base64 catalog") from exc
    plaintext = decrypt_binary(ciphertext)
    try:
        parsed = parse_document(plaintext.decode("utf-8"))
        if (not isinstance(parsed, dict) or
                not isinstance(parsed.get("Version"), str) or not parsed["Version"] or
                any(not isinstance(parsed.get(section), list) for section in ROOT_KEYS)):
            raise CatalogError("Unexpected APNA catalog schema")
        for group in ("Free_servers", "Premium_servers", "Vip_servers", "Private_servers", "Payloads"):
            if group in parsed and (not isinstance(parsed[group], list) or
                    any(not isinstance(item, dict) for item in parsed[group])):
                raise CatalogError("Unexpected APNA catalog records")
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        if isinstance(exc, CatalogError):
            raise
        raise CatalogError("Unsupported APNA JSON structure") from exc
    return plaintext


def run(data: bytes) -> str:
    """Catalog worker contract; output is complete unmodified JSON."""
    return decode_json_bytes(data).decode("utf-8")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CatalogError("Fixed source attempted a redirect")


def _plain_get(url: str, timeout: int = 25) -> bytes:
    """One plain GET exactly as the app makes it (no Range, no extra headers).

    Returns the body only when its length matches Content-Length (when the
    server sends one); raises CatalogError / IncompleteRead otherwise.
    """
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"})
    with build_opener(_NoRedirect()).open(request, timeout=timeout) as response:
        if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
            raise CatalogError("Invalid remote response")
        declared = response.headers.get("Content-Length")
        data = response.read(MAX_INPUT + 1)
    if not data or len(data) > MAX_INPUT:
        raise CatalogError("Remote response exceeds limits")
    if declared is not None and len(data) != int(declared):
        raise CatalogError("Truncated remote response")
    return data


def _ranged_get(url: str, timeout: int = 25) -> bytes:
    """Transport fallback: resume a dropped transfer with Range requests.

    The app itself never sends Range; this is only used here when a plain GET
    cannot complete (the updater host drops connections mid-body from some
    networks). Each resumed piece still carries the same User-Agent and
    Accept-Encoding: identity headers, and the assembled bytes are validated
    by length and by the XXTEA/JSON decode afterwards.
    """
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"})
    with build_opener(_NoRedirect()).open(request, timeout=timeout) as response:
        total = int(response.headers["Content-Length"])
        response.read(0)
    if not total or total > MAX_INPUT:
        raise CatalogError("Invalid remote response length")
    out = bytearray()
    chunk = 16 * 1024
    for start in range(0, total, chunk):
        end = min(start + chunk - 1, total - 1)
        cursor = start
        attempts = 0
        while cursor <= end:
            attempts += 1
            if attempts > 30:
                raise CatalogError("Ranged resume failed")
            ranged = Request(url, headers={
                "User-Agent": USER_AGENT,
                "Accept-Encoding": "identity",
                "Range": f"bytes={cursor}-{end}",
            })
            try:
                with build_opener(_NoRedirect()).open(ranged, timeout=timeout) as response:
                    if response.status != 206:
                        raise CatalogError("Range request rejected")
                    body = response.read()
                out += body
                cursor += len(body)
            except http.client.IncompleteRead as exc:
                out += exc.partial
                cursor += len(exc.partial)
            except OSError:
                time.sleep(1)
            if cursor <= end:
                time.sleep(0.3)
    if len(out) != total:
        raise CatalogError("Truncated remote response")
    return bytes(out)


def download(url: str = CATALOG_URL) -> bytes:
    """Download the fixed official catalog, replicating the app's GET first."""
    last_error: Exception | None = None
    for _ in range(3):
        try:
            return _plain_get(url)
        except (CatalogError, OSError) as exc:
            last_error = exc
            time.sleep(1)
    try:
        return _ranged_get(url)
    except (CatalogError, OSError) as exc:
        raise CatalogError("Unable to download official APNA Tunnel Lite catalog") from (exc or last_error)


def _member(archive: zipfile.ZipFile, name: str, limit: int) -> bytes:
    files = [item for item in archive.infolist() if item.filename == name]
    if len(files) != 1 or files[0].file_size > limit:
        raise CatalogError("Missing/duplicate/oversized APK member")
    with archive.open(files[0]) as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise CatalogError("APK member size exceeds limit")
    return data


def from_apks(path: Path) -> bytes:
    """Read only exact base.apk/assets/janur.json, never execute APK contents."""
    try:
        if path.stat().st_size > MAX_BUNDLE:
            raise CatalogError("Bundle size exceeds limit")
        with zipfile.ZipFile(path) as outer:
            if path.suffix.lower() == ".apk":
                return _member(outer, "assets/janur.json", MAX_INPUT)
            base_apk = _member(outer, "base.apk", MAX_BUNDLE)
        with zipfile.ZipFile(io.BytesIO(base_apk)) as inner:
            return _member(inner, "assets/janur.json", MAX_INPUT)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise CatalogError("Invalid APK/APKS") from exc


def summary(plaintext: bytes) -> dict:
    """Counts only: avoid leaking stored users, passwords or payloads."""
    document = json.loads(plaintext)
    return {
        "provider": "apna-tunnel-lite",
        "complete": True,
        "version": document.get("Version") if isinstance(document.get("Version"), str) else None,
        "sections": list(document),
        "serverCounts": {
            group: len(document[group])
            for group in ("Free_servers", "Premium_servers", "Vip_servers", "Private_servers")
            if isinstance(document.get(group), list)
        },
        "payloadCount": len(document["Payloads"]),
        "plaintextBytes": len(plaintext),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=CATALOG_URL,
                        help="Fixed official catalog URL (default: the Lite updater URL)")
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--apks", type=Path, help="Read embedded janur.json from APK/APKS")
    src.add_argument("--input", type=Path, help="Read encrypted janur.json")
    src.add_argument("--stdin", action="store_true", help="Read encrypted Base64 on stdin")
    parser.add_argument("--summary", action="store_true", help="Print metadata without credentials")
    parser.add_argument("--output", type=Path, help="Write output in a private 0600 file")
    args = parser.parse_args()
    try:
        remote = all(item is None for item in (args.apks, args.input)) and not args.stdin
        if args.apks:
            encrypted = from_apks(args.apks)
        elif args.input:
            if args.input.stat().st_size > MAX_INPUT:
                raise CatalogError("Input too large")
            encrypted = args.input.read_bytes()
        elif args.stdin:
            encrypted = sys.stdin.buffer.read(MAX_INPUT + 1)
        else:
            encrypted = download(args.url)
        plaintext = decode_json_bytes(encrypted)
        result = (json.dumps(summary(plaintext), ensure_ascii=False, indent=2).encode("utf-8")
                  if args.summary else plaintext)
        output_path = args.output or (Path(DEFAULT_OUTPUT) if remote and not args.summary else None)
        if output_path:
            fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(result + b"\n" if args.summary else result)
            print(f"Guardado: {output_path}")
        else:
            sys.stdout.buffer.write(result + b"\n" if args.summary else result)
        return 0
    except (CatalogError, OSError) as exc:
        print(f"APNA Tunnel Lite decoder: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
