#!/usr/bin/env python3
"""ALTAUFIK VPN 5.01: catalog decoder, local or explicit HTTPS.

Requires PyCryptodome (Crypto.Cipher.AES).

Method verified in net.tcodes.altaufikvpn 5.01 (versionCode 44):
  - Download: MainActivity.L(Z Z) -> F2/n (AsyncTask) -> Apache
    DefaultHttpClient, HttpGet on the URL as-is, no own headers, no
    params, no auth. Body read as ISO-8859-1 lines concatenated.
    The second boolean is the "use_vip" preference: false fetches
    the free URL, true fetches the VIP URL. On failure the task
    returns the string "error".
  - Decrypt: M2/d.a -> org.apache.commons.ssl.OpenSSL.decrypt(
    "aes256", "mtscrypt", Base64.decode(body)), i.e. OpenSSL Salted__
    container, EVP_BytesToKey/MD5, AES-256-CBC/PKCS#7. On failure the
    app returns the input unchanged, so plain JSON starting with "{"
    is accepted as-is.
  - Version compare: the callback (D2/k) parses the JSON and compares
    "Version" with the stored version; if newer it offers the update
    and saves the raw encrypted response in SQLite system.db /
    tcodes_table (ID 1 = free, ID 2 = VIP).
  - Bundled catalog: assets/defconf (free) and assets/vip_defconf
    (VIP) are copied into that table on first run.

Live state (2026-11-17):
  - Free endpoint: HTTP 200 but body is only 2 bytes ("ff"),
    Last-Modified 2023-10-06. It does NOT decrypt; the app falls
    back to the bundled free catalog (Version 9.6).
  - VIP endpoint: HTTP 200, 670572 bytes, Last-Modified
    2026-03-19, decrypts to Version 9.5, 7 servers, 1458 tweaks.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
# Free catalog (use_vip=false). Dead as of 2026-11-17: HTTP 200, 2-byte body.
CATALOG_URL = "https://24clanvpn.com/updater/12e6a66d012aa0e8ae49de9dd9d1d4"
# VIP catalog (use_vip=true). Live and decrypting as of 2026-11-17.
VIP_URL = "https://24clanvpn.com/updater/6ccbf3270197580767739262e2bcef"
# The app fetches with Apache DefaultHttpClient (F2/n) and sets no headers
# of its own; this is the User-Agent that stack sends implicitly.
USER_AGENT = "Apache-HttpClient/UNAVAILABLE (java 1.4)"
# Shared OpenSSL format passphrase from M2/d, not an account credential.
CATALOG_PASSPHRASE = b"mtscrypt"
LIST_FIELDS = ("Servers", "PremiumServers", "Tweaks", "PremiumTweaks")
# Synthetic self-test vector: {"Version":"99.9","Message":"self-test",
# "Servers":[{"Name":"T1"}],"Tweaks":[{"Name":"P1","Payload":"x"}]}
# encrypted with the same method (EVP_BytesToKey/MD5 + AES-256-CBC,
# salt 0102030405060708).
_SELF_TEST_VECTOR = (
    "U2FsdGVkX18BAgMEBQYHCASdOupMZ1L5zwMs5h0UNuZ8mQcM5KvDPPttD1a9N7nas9jILeo5oHpYodMsnmDdngDlyHsjvKozRdQ0cdEn9ecAKTLRYEKFn1+whvPKQAa8yBxGvkao2E935BJgA7Ho1spRgG9tXhBqdWd5xjj5yeH7BOk9ni7hqE51ltySFJ/D"
)


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
        raise DecodeError("FORMAT_ERROR", "Se esperaba Base64 estándar.")
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
        # strict=False: the live catalog carries raw control characters
        # inside string values (org.json tolerates them, as does the app).
        doc = json.loads(data, object_pairs_hook=_unique, parse_constant=_nonfinite, strict=False)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("INVALID_JSON", "JSON inválido o con claves duplicadas.") from exc
    if not isinstance(doc, dict):
        raise DecodeError("WRONG_DOCUMENT", "El catálogo debe contener un objeto JSON.")
    return _validate(doc)


def _evp_bytes_to_key(password: bytes, salt: bytes) -> tuple[bytes, bytes]:
    """OpenSSL EVP_BytesToKey, MD5, 1 iteration: 32-byte key + 16-byte IV."""
    material, previous = b"", b""
    while len(material) < 48:
        previous = hashlib.md5(previous + password + salt).digest()
        material += previous
    return material[:32], material[32:48]


def decrypt_catalog_text(data: bytes | str) -> str:
    text = _text(data)
    if text.startswith("{"):
        return text  # M2/d.a returns plaintext unchanged if OpenSSL cannot decode it.
    raw = _base64(text)
    if not raw.startswith(b"Salted__"):
        raise DecodeError("FORMAT_ERROR", "Se esperaba el contenedor OpenSSL Salted__ del catálogo.")
    if len(raw) < 32 or (len(raw) - 16) % 16:
        raise DecodeError("TRUNCATED", "El catálogo contiene bloques AES incompletos.")
    salt = raw[8:16]
    key, iv = _evp_bytes_to_key(CATALOG_PASSPHRASE, salt)
    try:
        plain = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(raw[16:]), AES.block_size)
        return plain.decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("DECRYPT_FAILED", "No se pudo descifrar este catálogo.") from exc


def decode(data: bytes | str) -> dict:
    doc = _json(decrypt_catalog_text(data))
    if not any(field in doc for field in LIST_FIELDS):
        raise DecodeError("WRONG_DOCUMENT", "No hay listas de servidores o tweaks en el catálogo.")
    for field in LIST_FIELDS:
        if field in doc and (not isinstance(doc[field], list) or any(not isinstance(v, dict) for v in doc[field])):
            raise DecodeError("WRONG_DOCUMENT", "Las listas de catálogo deben contener objetos completos.")
    return doc


def summary(doc: dict) -> dict:
    """Counts only: version plus the length of each catalog list. No values."""
    out = {"Version": doc.get("Version")}
    for field in LIST_FIELDS:
        if field in doc:
            out[field] = len(doc[field])
    tweaks = doc.get("Tweaks")
    if isinstance(tweaks, list):
        out["Payloads"] = sum(1 for t in tweaks if isinstance(t, dict) and t.get("Payload"))
    return out


def run(file_bytes: bytes | str) -> str | None:
    """Offline API: complete catalog JSON or None; never a partial list."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


class _HTTPSRedirect(HTTPRedirectHandler):
    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlsplit(newurl)
        if parsed.scheme != "https" or parsed.username is not None or parsed.password is not None:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_catalog(url: str = CATALOG_URL) -> bytes:
    try:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ValueError("invalid HTTPS URL")
        req = Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
        with build_opener(_HTTPSRedirect()).open(req, timeout=30) as response:
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


def _read(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


def _write_output(path: Path, rendered: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, rendered.encode("utf-8"))
    finally:
        os.close(fd)


def _self_test() -> dict:
    checks = {}
    # 1. Synthetic Salted__ envelope with the app's password.
    doc = decode(_SELF_TEST_VECTOR)
    checks["synthetic_envelope"] = (
        doc.get("Version") == "99.9"
        and len(doc.get("Servers", [])) == 1
        and len(doc.get("Tweaks", [])) == 1
    )
    # 2. Plain JSON passes through unchanged (as M2/d.a does on failure).
    checks["plain_json_passthrough"] = decode('{"Version":"1.0","Servers":[]}').get("Version") == "1.0"
    # 3. The free endpoint's dead body ("ff") is rejected, not invented.
    try:
        decode("ff")
        checks["dead_free_body_rejected"] = False
    except DecodeError:
        checks["dead_free_body_rejected"] = True
    checks["ok"] = all(checks.values())
    return checks


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=False)
    source.add_argument("file", nargs="?", type=Path, help="Respuesta del catálogo guardada localmente (o assets/defconf / vip_defconf del APK)")
    source.add_argument("--url", nargs="?", const=CATALOG_URL, help="Descarga explícita; por defecto usa el endpoint gratis")
    parser.add_argument("--vip", action="store_true", help="Usa el endpoint VIP en lugar del gratis (con --url, ignora la URL y usa la VIP)")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo con modo 0600; por defecto stdout")
    parser.add_argument("--summary", action="store_true", help="Imprimir solo versión y recuentos, sin valores")
    parser.add_argument("--self-test", action="store_true", help="Verifica un sobre Salted__ sintético y el rechazo del cuerpo muerto")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            result = _self_test()
            print(json.dumps(result, ensure_ascii=False))
            return 0 if result["ok"] else 1
        if args.url is not None:
            result = decode(fetch_catalog(VIP_URL if args.vip else args.url))
        elif args.file is not None:
            result = decode(_read(args.file))
        else:
            parser.error("se requiere un archivo, --url o --self-test")
        rendered = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            _write_output(args.output, rendered)
        if args.summary:
            sys.stdout.write(json.dumps(summary(result), ensure_ascii=False, indent=2, allow_nan=False) + "\n")
        elif not args.output:
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
