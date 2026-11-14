#!/usr/bin/env python3
"""UDP Thunder VPN 1.5: catalog decoder (APNA family: Base64 -> modified XXTEA).

Python 3.10+, solo biblioteca estandar. Sin dependencias.

Package com.udpthunder.vpn, versionCode 6, versionName 1.5, minSdk 23.
El APK es la version publica de Google Play (1.5); se descargo de APKPure
porque APKMirror no tenia listado. Sin cobertura previa en el repo de
SP-DECODE (86 carpetas revisadas; com.litron.udp es otra app).

Catalogo (UDPClient.i, Volley StringRequest; a.e / wh.c):

  GET https://freedomnavigate.com/updater/2ee4ec6e75df8910d98e7bb33f12e1
  (GET plano, sin cabeceras propias ni autenticacion. El servidor
  responde HTTP 200 con Content-Length 40424 y a veces corta la
  conexion a mitad del cuerpo: este script reanuda por rangos, igual
  que el de APNA Tunnel Lite. El User-Agent Dalvik/2.1.0 con
  Accept-Encoding: identity es aceptado por el servidor.)

  El cuerpo es una sola linea de Base64 -> XXTEA modificado
  (delta 0x9E5729B1, clave de formato "...|...", ultima palabra =
  longitud del texto plano) -> JSON {Version, Changelogs, UpdaterLink,
  UDPVersion, Username, Password, Free_servers[], Premium_servers[],
  Vip_servers[], Private_servers[], Payloads[]}.

  Es el mismo formato de APNA Tunnel Lite / TRM Tunnel / HX Tunnel /
  Handsome Fast / RJC Tunnel / HAMARA TUNNEL LITE (misma clave de
  catalogo "...|..." y mismo delta); solo cambian la URL, el nombre
  del asset (aug.json en vez de janu.json/janur.json) y la version.

  Los campos de nivel superior Username y Password vienen cifrados
  con el mismo XXTEA (Base64 -> XXTEA -> texto): son las credenciales
  SSH por defecto de los servidores (los servidores individuales
  traen username/password vacios). Este script los abre por defecto
  (opcion --keep-encoded para dejarlos tal cual).

  La app guarda el catalogo descargado como filesDir/aug.json y si no
  existe usa el asset incluido assets/aug.json (v18.0); ambos se
  descifran con el mismo metodo (wh.c). Este script acepta ese
  archivo con --file/--asset (ver UDP_Thunder_VPN_archivos.py).

LIVE STATUS (2026-11-13, verificado con --url): el endpoint responde
HTTP 200 (40.424 B) y el catalogo abre: Version "27.6", UDPVersion
"v2", 23 servidores libres (0 premium, 0 VIP, 0 privados) y 1
entrada de Payloads (plantilla con payload vacio, host/puerto
"Pulled"). Asset incluido: Version 18.0, 25 servidores libres.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import http.client
import json
import math
import re
import struct
import sys
import time
from pathlib import Path
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_INPUT = 8 * 1024 * 1024
DELTA = 0x9E5729B1  # XXTEA modificado (misma familia que APNA/TRM/HX).
KEY = b"...|..."  # Constante de formato del catalogo (wh.a en la app).
CATALOG_URL = "https://freedomnavigate.com/updater/2ee4ec6e75df8910d98e7bb33f12e1"
USER_AGENT = "Dalvik/2.1.0"
MASK = 0xFFFFFFFF
ROOT_KEYS = ("Free_servers", "Payloads")
DEFAULT_OUTPUT = "udp_thunder_vpn_catalogo.json"
ASSET_NAME = "aug.json"


class CatalogError(ValueError):
    """Invalid or unsupported UDP Thunder VPN catalog."""


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
    """Decrypt the little-endian XXTEA envelope with last-word length."""
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


def encrypt_binary(plaintext: bytes) -> bytes:
    """Encrypt with the same envelope (only used by --self-test)."""
    if len(plaintext) > MAX_INPUT:
        raise CatalogError("Plaintext too large")
    n = (len(plaintext) + 3) // 4
    values = list(struct.unpack("<" + "I" * n, plaintext.ljust(n * 4, b"\0")))
    values.append(len(plaintext))
    key = _words(KEY.ljust(16, b"\0"))
    total = 0
    rounds = 6 + 52 // len(values)
    z = values[-1]
    for _ in range(rounds):
        total = (total + DELTA) & MASK
        e = (total >> 2) & 3
        for index in range(len(values) - 1):
            y = values[index + 1]
            values[index] = (values[index] + _mx(total, y, z, index, e, key)) & MASK
            z = values[index]
        y = values[0]
        values[-1] = (values[-1] + _mx(total, y, z, len(values) - 1, e, key)) & MASK
        z = values[-1]
    return struct.pack("<" + "I" * len(values), *values)


def _open_credential(value):
    """Open a top-level Username/Password field (Base64 -> XXTEA -> UTF-8)."""
    if not isinstance(value, str) or not value:
        return value
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return value
    try:
        plain = decrypt_binary(raw)
    except CatalogError:
        return value
    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError:
        return value


def decode_json_bytes(data: bytes, keep_encoded: bool = False) -> bytes:
    """Return the complete, original UTF-8 JSON bytes.

    By default the top-level Username/Password fields are opened with
    the catalog XXTEA key (they are the default SSH credentials);
    --keep-encoded leaves them as the Base64 ciphertexts from the wire.
    """
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
        if (not isinstance(parsed, dict)
                or not isinstance(parsed.get("Version"), str) or not parsed["Version"]
                or any(not isinstance(parsed.get(section), list) for section in ROOT_KEYS)):
            raise CatalogError("Unexpected UDP Thunder catalog schema")
        for group in ("Free_servers", "Premium_servers", "Vip_servers", "Private_servers", "Payloads"):
            if group in parsed and (not isinstance(parsed[group], list)
                    or any(not isinstance(item, dict) for item in parsed[group])):
                raise CatalogError("Unexpected UDP Thunder catalog records")
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        if isinstance(exc, CatalogError):
            raise
        raise CatalogError("Unsupported UDP Thunder JSON structure") from exc
    if not keep_encoded:
        for field in ("Username", "Password"):
            if field in parsed:
                parsed[field] = _open_credential(parsed[field])
        return json.dumps(parsed, ensure_ascii=False).encode("utf-8")
    return plaintext


def decode(data: bytes, keep_encoded: bool = False) -> dict:
    """Decrypt a catalog body (Base64) or a plain catalog JSON and return the dict."""
    if isinstance(data, (bytes, str)):
        try:
            text = data.decode("utf-8-sig") if isinstance(data, bytes) else data
        except UnicodeDecodeError:
            text = None
        if text is not None:
            stripped = text.strip()
            if stripped.startswith("{"):
                doc = parse_document(stripped)
                if not isinstance(doc, dict) or ("Servers" not in doc and "Free_servers" not in doc):
                    raise CatalogError("The JSON is not a UDP Thunder catalog.")
                if not keep_encoded:
                    for field in ("Username", "Password"):
                        if field in doc:
                            doc[field] = _open_credential(doc[field])
                return doc
    return json.loads(decode_json_bytes(data, keep_encoded=keep_encoded).decode("utf-8"))


def run(data: bytes) -> str:
    """Return the decoded catalog as JSON text."""
    doc = decode(data)
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CatalogError("Fixed source attempted a redirect")


def _plain_get(url: str, timeout: int = 25) -> bytes:
    """One plain GET exactly as the app makes it (no Range, no extra headers)."""
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

    The app itself never sends Range; this is only used here when a plain
    GET cannot complete (the updater host drops connections mid-body
    from some networks). Each resumed piece still carries the same
    User-Agent and Accept-Encoding: identity headers, and the assembled
    bytes are validated by length and by the XXTEA/JSON decode afterwards.
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
        raise CatalogError("Unable to download official UDP Thunder VPN catalog") from (exc or last_error)


def summary(plaintext: bytes) -> dict:
    """Counts only: avoid leaking stored users, passwords or payloads."""
    document = json.loads(plaintext)
    return {
        "provider": "udp-thunder-vpn",
        "complete": True,
        "version": document.get("Version") if isinstance(document.get("Version"), str) else None,
        "udpVersion": document.get("UDPVersion"),
        "sections": list(document),
        "serverCounts": {
            group: len(document[group])
            for group in ("Free_servers", "Premium_servers", "Vip_servers", "Private_servers")
            if isinstance(document.get(group), list)
        },
        "payloadCount": len(document["Payloads"]),
        "plaintextBytes": len(plaintext),
    }


def _self_test() -> dict:
    """Verify XXTEA round-trip, the bundled asset and credential opening."""
    checks = {}
    sample = b'{"Version": "99.9", "Free_servers": [], "Payloads": []}'
    checks["xxtea_roundtrip"] = decrypt_binary(encrypt_binary(sample)) == sample
    checks["xxtea_one_byte"] = decrypt_binary(encrypt_binary(b"X")) == b"X"
    checks["xxtea_unicode"] = decrypt_binary(
        encrypt_binary("servidor \U0001f30d \u00e1".encode("utf-8"))) == "servidor \U0001f30d \u00e1".encode("utf-8")
    asset = Path(__file__).with_name(ASSET_NAME)
    if asset.exists():
        raw = asset.read_bytes()
        doc = decode(raw)
        checks["asset_version"] = doc.get("Version") == "18.0"
        checks["asset_free_servers"] = len(doc.get("Free_servers", [])) == 25
        checks["asset_payloads"] = len(doc.get("Payloads", [])) == 1
        checks["asset_credentials_opened"] = (
            isinstance(doc.get("Username"), str) and doc["Username"] != ""
            and doc["Username"] == doc.get("Password")
            and all(c.isprintable() for c in doc["Username"]))
        checks["asset_keep_encoded"] = (
            decode(raw, keep_encoded=True)["Username"] != doc["Username"])
    else:
        checks["asset_present"] = False
    try:
        bad = bytearray(encrypt_binary(sample))
        bad[len(bad) // 2] ^= 0x01
        decode(bytes(bad))
        checks["corrupt_rejected"] = False
    except CatalogError:
        checks["corrupt_rejected"] = True
    try:
        decode(b"not base64!!!")
        checks["garbage_rejected"] = False
    except CatalogError:
        checks["garbage_rejected"] = True
    return checks


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", nargs="?", const=CATALOG_URL, default=None,
                        help="Download the live catalog (default URL when no value is given)")
    parser.add_argument("--file", type=Path, help="Read an encrypted catalog file (e.g. filesDir/aug.json)")
    parser.add_argument("--asset", action="store_true", help="Decrypt the bundled aug.json asset")
    parser.add_argument("--stdin", action="store_true", help="Read encrypted Base64 on stdin")
    parser.add_argument("--keep-encoded", action="store_true",
                        help="Leave top-level Username/Password as Base64 ciphertexts")
    parser.add_argument("--summary", action="store_true", help="Print metadata without credentials")
    parser.add_argument("--self-test", action="store_true", help="Verify XXTEA, the bundled asset and credential opening")
    parser.add_argument("-o", "--output", type=Path, help="Write output to this file")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            result = _self_test()
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if all(result.values()) else 1
        if args.asset:
            asset = Path(__file__).with_name(ASSET_NAME)
            encrypted = asset.read_bytes()
        elif args.file is not None:
            if args.file.stat().st_size > MAX_INPUT:
                raise CatalogError("Input too large")
            encrypted = args.file.read_bytes()
        elif args.stdin:
            encrypted = sys.stdin.buffer.read(MAX_INPUT + 1)
        elif args.url is not None:
            encrypted = download(args.url)
        else:
            parser.error("se requiere --url, --file, --asset o --stdin (o --self-test)")
        plaintext = decode_json_bytes(encrypted, keep_encoded=args.keep_encoded)
        result = (json.dumps(summary(plaintext), ensure_ascii=False, indent=2).encode("utf-8")
                  if args.summary else plaintext)
        if args.output:
            args.output.write_bytes(result + b"\n" if args.summary else result)
            print(f"Guardado: {args.output}")
        else:
            sys.stdout.buffer.write(result + b"\n" if args.summary else result)
        return 0
    except (CatalogError, OSError) as exc:
        print(f"UDP Thunder VPN decoder: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
