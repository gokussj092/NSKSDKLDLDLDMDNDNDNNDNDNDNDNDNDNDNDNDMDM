#!/usr/bin/env python3
"""Click Tunnel (com.clicktunnel.vpn, versionCode 1, versionName 1.0): catalog decoder, local or explicit HTTPS.

Standalone Python 3.10+; needs pycryptodome (Crypto.Cipher.AES) for the
AES field ciphers. Use ~/workspace/http-custom-update/venv/bin/python.
No APK needed at runtime. For .sup/.wsuiou profile files, QR text and
cloud keys use Click_Tunnel_archivos.py.

Method verified by decompiling this APK (jadx 1.5.3; the app's strings
go through AbstractC0144Cp0.j(long), a DexGuard-style string table,
ported to Python and verified on known vectors in work/cp0.py):
  * Download: L0 case 10 ("FetchData") performs a plain GET
    (HttpURLConnection, connect/read timeout 5,000 ms, no custom
    headers, requires HTTP 200) of the DefUpdateUrL stored in
    SharedPreferences; the body goes to RunnableC2401i3 case 13, then
    H01.d(str). The default DefUpdateUrL (bundled asset res/raw/noobdev.js)
    is the GitHub raw URL in CATALOG_URL below. The "updater" URL is a
    separate package-update check only (C4 case 8), not the catalog.
  * Outer layer (H01.d -> I20.a): custom Base64 decode
    (AbstractC1228Xe.m: standard alphabet, skips invalid chars, stops
    at "=") -> XXTEA-modified (AbstractC3148mf.h): delta 0x9A7393B4,
    rounds (52/n)+6, little-endian words, length in the last word;
    key = first 16 bytes of UTF-8 of 32x U+3164 (Hangul filler).
    Result: the catalog JSON, still with encrypted string fields.
  * Field cipher C0972Sm.c (AbstractC1943eS.a): AES-256/CFB/NoPadding
    (CFB128), key = SHA-256 of an 83-char seed string (61 spaces + "'"
    + 12 spaces + "." + 8 spaces), IV = AbstractC1943eS.c. Used for
    every top-level string field (Main.v, try/catch, raw on failure),
    every Servers[] string field and every nested SlowDNS/UDP value.
  * Field cipher C0972Sm.d (OO0.a): AES/CBC/PKCS7Padding, key = the
    32-byte ASCII lowercase hex of MD5 of a 63-char seed string
    (29 spaces + "." + 33 spaces), IV = OO0.b. Used for every Tweaks[]
    string field (try/catch, raw on failure). The tweak "Flag" is
    plaintext "NOOB_DEV", not encrypted. Empty strings stay empty.
  * Version check (H01.d): if the decrypted "Version" is newer than the
    stored one, Main.v stores the raw response in SQLite table
    spkmoder_table (row ID 1, DB "system.Database") and parses the
    fields; otherwise "No Updates Available!". This script never
    merges local profiles; decode() returns the remote document as-is.

The catalog format has no MAC; structural validation is not
cryptographic authentication. The output JSON is the decrypted catalog
document minus the download-endpoint fields: the document itself carries
its own download URL in ``DefUpdateURL`` (it is CATALOG_URL) and the
package-update check URL in ``updater``. Per the SP-DECODE catalog rule
(the result JSON carries catalog data only, never the download APIs),
main() strips both keys from the saved/printed output; the download URL
lives in CATALOG_URL only.
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
import struct
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile

try:
    from Crypto.Cipher import AES
except ImportError as exc:  # pycryptodome, in the venv named in the docstring
    raise SystemExit(
        "Falta pycryptodome (Crypto.Cipher.AES). Usa "
        "~/workspace/http-custom-update/venv/bin/python."
    ) from exc

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
MASK = 0xFFFFFFFF
DELTA = (-1703701580) & MASK  # XXTEA variant delta 0x9A7393B4 (AbstractC3148mf.h).
# Outer XXTEA key: first 16 bytes of UTF-8 of 32x U+3164.
XXTEA_KEY = ("\u3164" * 32).encode("utf-8")[:16]
# Field-cipher seeds, extracted verbatim from the jadx sources
# (AbstractC1943eS.java, OO0.java) and written as explicit runs so the
# space counts cannot drift. Verified keys:
#   SHA-256(seed_c) = 974f2a3d5e5c0d50ca2c3e8aae1c4f79ddccf43cef90f9984a7e09fdc09bc482
#   MD5 hex(seed_d) = d880ed3291f96d9464a2c935e829837f (ASCII, AES-256 key)
SEED_CFB = " " * 61 + "'" + " " * 12 + "." + " " * 8   # 83 chars
SEED_CBC = " " * 29 + "." + " " * 33                    # 63 chars
KEY_CFB = hashlib.sha256(SEED_CFB.encode("utf-8")).digest()
KEY_CBC = hashlib.md5(SEED_CBC.encode("utf-8")).hexdigest().encode("ascii")
IV_CFB = bytes([78, 106, 44, 129, 83, 217, 180, 167, 144, 63, 104, 92, 161, 239, 36, 121])
IV_CBC = bytes([60, 127, 26, 157, 85, 227, 192, 178, 142, 33, 109, 74, 151, 255, 19, 98])
# Default catalog URL (DefUpdateUrL from the bundled asset res/raw/noobdev.js;
# identical in the live response). Fixed app constant, not a user credential.
CATALOG_URL = "https://raw.githubusercontent.com/uptechvpn/Click-Tunnel/refs/heads/main/Click%20Tunnel"
USER_AGENT = "Dalvik/2.1.0"  # Platform-agent family of the app's HTTP stack.
BUNDLED_ASSET = "res/raw/noobdev.js"
LIST_FIELDS = ("Servers", "Tweaks")


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
    # AbstractC1228Xe.m: standard alphabet, skips invalid chars, stops at "=".
    compact = re.sub(r"[^A-Za-z0-9+/=]", "", text).split("=", 1)[0]
    if not compact or len(compact) % 4 == 1:
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


def decrypt_catalog_bytes(data: bytes | str) -> bytes:
    """I20.a: Base64 -> XXTEA-modified (last-word length) -> JSON bytes."""
    encrypted = _base64(_text(data))
    if len(encrypted) < 8 or len(encrypted) % 4:
        raise DecodeError("TRUNCATED", "El catálogo no contiene palabras XXTEA completas.")
    values = list(struct.unpack("<" + "I" * (len(encrypted) // 4), encrypted))
    key = struct.unpack("<4I", XXTEA_KEY[:16].ljust(16, b"\0"))
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


def sm_c(value: str) -> str:
    """C0972Sm.c: AES-256/CFB128/NoPadding, Base64 input -> UTF-8 string."""
    raw = base64.b64decode(value, validate=True)
    return AES.new(KEY_CFB, AES.MODE_CFB, iv=IV_CFB, segment_size=128).decrypt(raw).decode("utf-8")


def sm_d(value: str) -> str:
    """C0972Sm.d: AES/CBC/PKCS7, Base64 input -> UTF-8 string.

    The key is the 32-byte ASCII lowercase MD5 hex of the seed (AES-256).
    """
    raw = base64.b64decode(value, validate=True)
    plain = AES.new(KEY_CBC, AES.MODE_CBC, iv=IV_CBC).decrypt(raw)
    if not plain:
        raise ValueError("empty plaintext")
    pad = plain[-1]
    if pad < 1 or pad > 16 or plain[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad PKCS7 padding")
    return plain[:-pad].decode("utf-8")


def _try(fn, value: str) -> str:
    """The app wraps every field decrypt in try/catch and keeps the raw
    value on failure (Main.v; AbstractC1201Wq0.h does the same)."""
    if not value:
        return value
    try:
        return fn(value)
    except Exception:
        return value


def _decrypt_fields(value, fn):
    if isinstance(value, str):
        return _try(fn, value)
    if isinstance(value, dict):
        return {k: _decrypt_fields(v, fn) for k, v in value.items()}
    return value


def _catalog_json(data) -> dict:
    doc = _json(data)
    if not any(field in doc for field in LIST_FIELDS):
        raise DecodeError("WRONG_DOCUMENT", "No hay listas de servidores o payloads en el catálogo.")
    for field in LIST_FIELDS:
        if field in doc and (not isinstance(doc[field], list) or any(not isinstance(v, dict) for v in doc[field])):
            raise DecodeError("WRONG_DOCUMENT", "Las listas de catálogo deben contener objetos completos.")
    return doc


def decode(data: bytes | str) -> dict:
    """Offline API: outer XXTEA decrypt, then field-decrypt every string
    value (top-level + Servers[] with sm.c, Tweaks[] with sm.d)."""
    doc = _catalog_json(decrypt_catalog_bytes(data))
    for key, value in doc.items():
        if key == "Servers":
            doc[key] = [_decrypt_fields(item, sm_c) for item in value]
        elif key == "Tweaks":
            doc[key] = [_decrypt_fields(item, sm_d) for item in value]
        elif isinstance(value, str):
            doc[key] = _try(sm_c, value)
    return doc


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


def _headers():
    # The app sends no custom headers; HttpURLConnection only adds the
    # platform User-Agent. GitHub raw answers any User-Agent (verified).
    return {"User-Agent": USER_AGENT}


def fetch_catalog(url: str = CATALOG_URL) -> bytes:
    """Plain GET exactly as the app makes it (5 s timeouts, HTTP 200)."""
    _https_url(url)
    opener = build_opener(_HTTPSRedirect())
    for _ in range(3):
        try:
            req = Request(url, headers=_headers(), method="GET")
            with opener.open(req, timeout=5) as response:
                if response.status != 200:
                    raise DecodeError("DOWNLOAD_FAILED", "El endpoint no devolvió 200.")
                data = response.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise DecodeError("SIZE_LIMIT", "La respuesta supera el límite de tamaño.")
            return data
        except DecodeError:
            raise
        except (HTTPError, URLError, OSError, ValueError) as exc:
            code = "ACCESS_DENIED" if isinstance(exc, HTTPError) and exc.code in (401, 403) else "DOWNLOAD_FAILED"
            last = DecodeError(code, "No se pudo descargar el catálogo mediante HTTPS.")
            last.__cause__ = exc
    raise last


def read_bundled(apk_path: Path) -> bytes:
    """res/raw/noobdev.js from the APK, or from base.apk inside a .apks bundle."""
    try:
        with zipfile.ZipFile(apk_path) as zf:
            names = zf.namelist()
            if BUNDLED_ASSET in names:
                return zf.read(BUNDLED_ASSET)
            if "base.apk" in names:
                inner = zf.read("base.apk")
                with zipfile.ZipFile(__import__("io").BytesIO(inner)) as base:
                    return base.read(BUNDLED_ASSET)
            raise KeyError(BUNDLED_ASSET)
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
                        help="Lee res/raw/noobdev.js del APK o del .apks indicado")
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
        # Regla del catálogo SP-DECODE: el JSON de resultado lleva solo los
        # datos del catálogo, nunca las APIs de descarga. El documento mismo
        # trae su URL de descarga en DefUpdateURL (es CATALOG_URL) y la URL
        # de comprobación de actualización en updater; se quitan de la salida.
        doc.pop("DefUpdateURL", None)
        doc.pop("updater", None)
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
