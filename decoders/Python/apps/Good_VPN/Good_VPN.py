#!/usr/bin/env python3
"""GOOD VPN (com.ovpnsevice.goodvpn, versionCode 30, versionName 3.0): catalog decoder, local or explicit HTTPS.

Standalone Python 3.10+, standard library only; no APK needed at runtime.
For the app's cached catalog file (filesDir/profile.json, same encrypted
format) use Good_VPN_archivos.py. GOOD VPN has no user file import and no
live custom text/link scheme (see README.md).

Method verified by decompiling this APK (jadx 1.5.3, R8 string table
recovered with the same algorithm as the app's jw1.x; native lib
libapi-good.so read directly):
  * Download: MainActivity.z() builds an OkHttp request (ne.H) for the
    fixed URL returned by the native MainDetail.a() (libapi-good.so,
    Java_com_ovpnsevice_goodvpn_MainDetail_a) and enqueues it (ne.G /
    ko0); the response callback is tc.c, which reads the body as a UTF-8
    string when the response is successful (2xx) and posts it to nc0.
    The request is a plain GET with no app headers and no body; OkHttp
    5.2.1 sends User-Agent "okhttp/5.2.1" by default. The server answers
    200 to any User-Agent (verified with curl's default UA and Mozilla).
  * Handler nc0: an2.c(hc1.g(response), MainDetail.b().getBytes("UTF-8"))
    = hand-rolled Base64 decode -> XXTEA decrypt (delta 0x2E0BA747,
    key "goodvpn090529", zero-padded to 16 bytes, last-word length) ->
    JSON. MainDetail.b() is the second native string in libapi-good.so
    (Java_com_ovpnsevice_goodvpn_MainDetail_b). The JSON is parsed and
    its "Version" (a double, e.g. "21.8") is compared with the stored
    version; when it is newer the app shows the "Message" update notice
    and saves the document re-encrypted with od.g (XXTEA encrypt +
    Base64) into filesDir + "/profile.json" (ys case 2). xm0.a() reads
    that file back with the same an2.c/hc1.g pair and normalises legacy
    field names (Name -> ServerName, Flag -> ServerFlag, SSLPort ->
    OpenVPNSSLPort/SSHSSLPort, OvpnCertificate -> setOpenVPN, and the
    Networks equivalents).
  * The format has no MAC; structural validation is not cryptographic
    authentication.
  * Inner values: several catalog fields are themselves Base64-encoded
    (Android Base64.DEFAULT, newline-wrapped every 76 chars) and the
    app decodes them at use time with od.h (ea1 getters: SERVER_HOST,
    USERNAME_SERVER, PASSWORD_SERVER, OPENVPN_CINFIG, PAYLOAD,
    PROXY_HOST, DNSTT_DNS, DNSTT_PUBLICKEY; MainActivity.G decodes the
    server's V2Ray field the same way). This script decodes exactly
    those fields (see B64_FIELDS); a field that does not decode is kept
    as-is and reported in the summary, never invented.
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

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
MASK = 0xFFFFFFFF
DELTA = 772515655  # XXTEA variant delta 0x2E0BA747 (an2.c).
# Fixed format key from libapi-good.so (MainDetail.b), not an account
# credential. an2.c pads/truncates it to 16 bytes with zeroes.
CATALOG_KEY = b"goodvpn090529"
# Fixed catalog URL from libapi-good.so (MainDetail.a), not a credential.
CATALOG_URL = "https://raw.githubusercontent.com/Anurak2534/ohmvpn/refs/heads/main/newgood.json"
USER_AGENT = "okhttp/5.2.1"  # Default User-Agent of the app's OkHttp 5.2.1 stack.
LIST_FIELDS = ("Servers", "Networks")
# Catalog fields the app itself Base64-decodes at use time (od.h).
# ServerIP/Username/Password/setOpenVPN/V2Ray/ServerDNS/Cloudfront/
# NameServer/PublicKey/UDPConfig (Servers); Payload/SquidProxy/Sni
# (Networks); setOpenVPN also occurs at top level.
B64_FIELDS = frozenset({
    "ServerIP", "Username", "Password", "setOpenVPN", "V2Ray",
    "ServerDNS", "Cloudfront", "NameServer", "PublicKey", "UDPConfig",
    "Payload", "SquidProxy", "Sni",
})


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
    compact = re.sub(r"\s+", "", text)
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
    """an2.c: Base64 -> XXTEA (last-word length) -> JSON bytes."""
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


def _try_b64(value: str) -> str | None:
    """Decode one inner Base64 value (whitespace-insensitive).

    Returns the decoded UTF-8 text only when it is fully printable;
    otherwise None so the caller keeps the original value.
    """
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 4 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact) or len(compact) % 4 == 1:
        return None
    try:
        raw = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
        text = raw.decode("utf-8")
    except (ValueError, binascii.Error, UnicodeError):
        return None
    if not all(ch.isprintable() or ch in "\r\n\t" for ch in text):
        return None
    return text


def _decode_inner(doc: dict) -> list[str]:
    """Base64-decode the catalog fields the app decodes at use time.

    Returns the sorted list of field names that stayed encoded because
    their value did not decode (empty when everything decoded).
    """
    left = set()

    def walk(node):
        if isinstance(node, dict):
            for field, value in node.items():
                if isinstance(value, str) and field in B64_FIELDS and value.strip():
                    decoded = _try_b64(value)
                    if decoded is None:
                        left.add(field)
                    else:
                        node[field] = decoded
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(doc)
    return sorted(left)


def _catalog_json(data) -> dict:
    doc = _json(data)
    if not any(field in doc for field in LIST_FIELDS):
        raise DecodeError("WRONG_DOCUMENT", "No hay listas de servidores o payloads en el catálogo.")
    for field in LIST_FIELDS:
        if field in doc and (not isinstance(doc[field], list) or any(not isinstance(v, dict) for v in doc[field])):
            raise DecodeError("WRONG_DOCUMENT", "Las listas de catálogo deben contener objetos completos.")
    return doc


def decode(data: bytes | str) -> dict:
    """Offline API: decrypt the complete catalog, inner values included.

    The returned dict keeps every catalog field; fields listed in
    B64_FIELDS are Base64-decoded the way the app decodes them (od.h).
    A field that does not decode is left as-is (see summary()).
    """
    doc = _catalog_json(decrypt_catalog_bytes(data))
    _decode_inner(doc)
    return doc


def undecoded_fields(doc: dict) -> list[str]:
    """Field names (B64_FIELDS) whose stored value is still Base64."""
    left = set()

    def walk(node):
        if isinstance(node, dict):
            for field, value in node.items():
                if isinstance(value, str) and field in B64_FIELDS and value.strip():
                    if _try_b64(value) is not None:
                        left.add(field)
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(doc)
    return sorted(left)


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
    out["undecoded_fields"] = undecoded_fields(doc)
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


def fetch_catalog(url: str = CATALOG_URL) -> bytes:
    """Plain GET exactly as the app makes it (OkHttp, no app headers)."""
    _https_url(url)
    opener = build_opener(_HTTPSRedirect())
    last_exc = None
    for _ in range(3):
        try:
            req = Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
            with opener.open(req, timeout=25) as response:
                if response.status != 200:
                    raise DecodeError("DOWNLOAD_FAILED", "El endpoint no devolvió 200.")
                data = response.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise DecodeError("SIZE_LIMIT", "La respuesta supera el límite de tamaño.")
            return data
        except DecodeError:
            raise
        except (HTTPError, URLError, HTTPException, OSError, ValueError) as exc:
            last_exc = exc
    code = "ACCESS_DENIED" if isinstance(last_exc, HTTPError) and last_exc.code in (401, 403) else "DOWNLOAD_FAILED"
    raise DecodeError(code, "No se pudo descargar el catálogo mediante HTTPS.") from last_exc


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
    source.add_argument("--stdin", action="store_true", help="Lee la respuesta cifrada desde stdin")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo; no sobrescribe")
    parser.add_argument("--summary", action="store_true",
                        help="Solo recuentos (versión y tamaños de lista), sin valores descifrados")
    args = parser.parse_args(argv)
    try:
        if args.url is not None:
            raw = fetch_catalog(args.url)
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
