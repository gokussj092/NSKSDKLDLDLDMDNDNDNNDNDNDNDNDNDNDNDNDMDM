#!/usr/bin/env python3
"""HX Tunnel VPN Hx-Build15: catalog decoder, local or explicit HTTPS.

Build15 verified 2026-11-25: same endpoint, key (b"Princie!") and XXTEA
variant (delta 0x9e5729b1) as Build14; live catalog Version 26.12
(24 free servers, 714 payloads) downloaded and decoded in vivo.
For .hxt files use hx_archivos.py.

Audit 2026-11-25: the top-level "Username"/"Password" values in the
decrypted catalog JSON are NOT plaintext — each is a Base64 XXTEA blob
(same key/delta as the catalog envelope; APK AbstractC4624vm.c routine)
that decrypts to a 32-char hex shared credential. decode() decrypts
both fields; every other catalog value was verified plaintext.

Standalone Python 3.10+, standard library only; no APK needed at runtime.
For .hxt files or encrypted profile text use hx_archivos.py.
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

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
MASK = 0xffffffff
DELTA = (-1638454863) & MASK  # APK XXTEA variant: 0x9e5729b1.
# Shared format constant in AbstractC0282Km, not an account credential.
CATALOG_KEY = b"Princie!"
CATALOG_URL = "https://hxrelay.us/updater/e7aa9907021632c39b0e0573e11861"
# Build14 used https://ctxrelay.online/updater/<same path>; both hosts serve
# the byte-identical catalog (verified 2026-11-25, SHA-256 20cda1eb...).
USER_AGENT = "HX Tunnel VPN/Hx-Build15"
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


def _decrypt_credential_fields(doc: dict) -> dict:
    """Decrypt the top-level shared credentials, if present.

    The catalog JSON carries "Username"/"Password" as Base64 XXTEA blobs
    encrypted with the same key/delta as the catalog envelope itself
    (APK AbstractC4624vm.c: Base64-decode, XXTEA-decrypt, UTF-8).
    Each decrypts to a 32-char lowercase-hex shared credential
    (verified by exact re-encryption round-trip against the live
    catalog v26.12 and the bundled assets/gremlin.json v25.47).
    A value that does not decrypt is left untouched, so a future
    catalog shipping the credentials in clear still decodes.
    """
    for field in ("Username", "Password"):
        value = doc.get(field)
        if isinstance(value, str) and value:
            try:
                doc[field] = decrypt_catalog_bytes(value).decode("utf-8")
            except (DecodeError, UnicodeError):
                pass
    return doc


def _catalog_json(data) -> dict:
    doc = _json(data)
    if not any(field in doc for field in LIST_FIELDS):
        raise DecodeError("WRONG_DOCUMENT", "No hay listas de servidores o payloads en el catálogo.")
    for field in LIST_FIELDS:
        if field in doc and (not isinstance(doc[field], list) or any(not isinstance(v, dict) for v in doc[field])):
            raise DecodeError("WRONG_DOCUMENT", "Las listas de catálogo deben contener objetos completos.")
    return _decrypt_credential_fields(doc)


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


def fetch_catalog(url: str = CATALOG_URL, attempts: int = 5) -> bytes:
    # The host truncates the body mid-transfer from some networks (the
    # response always announces the full Content-Length, but the socket
    # closes early at a 16 KiB boundary). Retry the whole GET until the
    # announced length arrives; a truncated body cannot decrypt (XXTEA
    # needs the complete block, length word included).
    last_exc: Exception | None = None
    for _ in range(max(1, attempts)):
        try:
            _https_url(url)
            req = Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
            with build_opener(_HTTPSRedirect()).open(req, timeout=20) as response:
                if response.status != 200:
                    raise OSError("unexpected HTTP status")
                data = response.read(MAX_BYTES + 1)
                announced = response.headers.get("Content-Length")
                if announced is not None and len(data) != int(announced):
                    raise OSError("truncated body")
        except HTTPError as exc:
            code = "ACCESS_DENIED" if exc.code in (401, 403) else "DOWNLOAD_FAILED"
            raise DecodeError(code, "El endpoint no devolvió un catálogo accesible.") from exc
        except (OSError, ValueError, URLError, HTTPException) as exc:
            last_exc = exc
            continue
        if len(data) > MAX_BYTES:
            raise DecodeError("SIZE_LIMIT", "La respuesta supera el límite de tamaño.")
        return data
    raise DecodeError("DOWNLOAD_FAILED", "No se pudo descargar el catálogo mediante HTTPS.") from last_exc


def _read(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


def _xxtea_encrypt_block(plain: bytes) -> bytes:
    """Encrypt helper used ONLY by --self-test (round-trip check)."""
    import struct as _st
    pad = (-len(plain)) % 4
    data = plain + b"\0" * pad
    values = list(_st.unpack("<" + "I" * (len(data) // 4), data))
    values.append(len(plain))
    count = len(values)
    key = _st.unpack("<4I", CATALOG_KEY[:16].ljust(16, b"\0"))
    total = 0
    rounds = 6 + 52 // count
    z = values[-1]
    for _ in range(rounds):
        total = (total + DELTA) & MASK
        e = (total >> 2) & 3
        for position in range(count):
            y = values[(position + 1) % count]
            values[position] = (values[position] + _mx(total, y, z, position, e, key)) & MASK
            z = values[position]
    return _st.pack("<" + "I" * count, *values)


def self_test() -> int:
    """No-network checks: XXTEA round-trip, base64 handling, error paths."""
    import base64 as _b64
    failures = []
    doc = {"Version": "test", "Free_servers": [], "Premium_servers": [],
           "Vip_servers": [], "Private_servers": [],
           "Payloads": [{"friendly_name": "t", "payload": "GET / [crlf]"}]}
    raw = json.dumps(doc, ensure_ascii=False).encode("utf-8")
    try:
        enc = _b64.b64encode(_xxtea_encrypt_block(raw)).decode()
        assert decode(enc) == doc
    except Exception as exc:  # noqa: BLE001 - self-test reports only
        failures.append(f"round-trip: {exc!r}")
    # Credential fields: Base64 XXTEA blobs decrypt to the hex plaintext.
    # (Synthetic test vectors only — never real catalog credentials.)
    try:
        cred_doc = dict(doc)
        cred_doc["Username"] = _b64.b64encode(_xxtea_encrypt_block(b"0123456789abcdef0123456789abcdef")).decode()
        cred_doc["Password"] = _b64.b64encode(_xxtea_encrypt_block(b"fedcba9876543210fedcba9876543210")).decode()
        enc = _b64.b64encode(_xxtea_encrypt_block(json.dumps(cred_doc, ensure_ascii=False).encode("utf-8"))).decode()
        got = decode(enc)
        assert got["Username"] == "0123456789abcdef0123456789abcdef", got["Username"]
        assert got["Password"] == "fedcba9876543210fedcba9876543210", got["Password"]
    except Exception as exc:  # noqa: BLE001 - self-test reports only
        failures.append(f"credential round-trip: {exc!r}")
    for bad, want in [("!!!", "FORMAT_ERROR"), ("AAAA", "TRUNCATED")]:
        try:
            decode(bad)
            failures.append(f"bad input {bad!r} accepted")
        except DecodeError as exc:
            if exc.code != want:
                failures.append(f"bad input {bad!r}: got {exc.code}, want {want}")
    if failures:
        print("SELF-TEST FAIL: " + "; ".join(failures), file=sys.stderr)
        return 1
    print("SELF-TEST OK: XXTEA round-trip + error paths (no network, no real catalog)")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=False)
    source.add_argument("file", nargs="?", type=Path, help="Respuesta del catálogo guardada localmente")
    source.add_argument("--url", nargs="?", const=CATALOG_URL, help="Descarga explícita; por defecto usa el endpoint original")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo; por defecto stdout")
    parser.add_argument("--self-test", action="store_true", help="Comprobaciones sin red y salir")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.file is None and args.url is None:
        parser.error("one of the arguments file --url is required")
    try:
        result = decode(fetch_catalog(args.url) if args.url is not None else _read(args.file))
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
