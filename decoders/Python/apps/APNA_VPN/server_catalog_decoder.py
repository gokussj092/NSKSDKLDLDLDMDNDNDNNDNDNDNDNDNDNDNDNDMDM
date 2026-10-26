#!/usr/bin/env python3
"""APNA VPN 3.9: catálogo, archivos y texto, solo biblioteca estándar.

run() is offline; only the explicit CLI/download path accesses the fixed source.
Neither modified XXTEA nor the profile XOR format authenticates ciphertext.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import io
import json
import math
import os
from pathlib import Path
import re
import struct
import sys
import zipfile
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_INPUT = 8 * 1024 * 1024
MAX_BUNDLE = 100 * 1024 * 1024
DELTA = 0x9E5729B1  # APNA 3.9 Dalvik LBm.b, NOT the standard XXTEA delta
KEY = b"...|..."  # Fixed catalog-format constant from LBm.a.
PROFILE_KEY = b"4%PdXch>fkP]"  # Original ARM64 xorWithKey, twelve bytes.
PROFILE_PREFIX = "apnavpn://"
CATALOG_URL = "https://paperonboard.com/updater/3c3c4c58d864ca394da16656b4d0c4"
USER_AGENT = "Dalvik/2.1.0"  # Reproduces the HttpURLConnection platform agent family.
MASK = 0xFFFFFFFF
ROOT_KEYS = ("Free_servers", "Payloads")


class CatalogError(ValueError):
    """Invalid or unsupported APNA catalog."""


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
            pending.extend((item, depth+1) for item in value.values())
        elif isinstance(value, list):
            pending.extend((item, depth+1) for item in value)
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


def decode_profile_bytes(data: bytes) -> bytes:
    """Hex -> fixed XOR -> JNI modified UTF-8 -> complete JSON, no password input."""
    if not isinstance(data, bytes) or not data or len(data) > MAX_INPUT:
        raise CatalogError("Invalid profile input size")
    try:
        token = data.decode("utf-8-sig").strip()
        if token.lower().startswith(PROFILE_PREFIX):
            token = token[len(PROFILE_PREFIX):]
        if not token or len(token) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", token):
            raise CatalogError("Invalid APNA hex profile")
        raw = bytes.fromhex(token)
        plain = bytes(b ^ PROFILE_KEY[i % len(PROFILE_KEY)] for i, b in enumerate(raw))
        # JNI encodes supplementary characters as surrogate pairs, not four bytes.
        text = plain.replace(b"\xc0\x80", b"\0").decode("utf-8", "surrogatepass")
        text = text.encode("utf-16-le", "surrogatepass").decode("utf-16-le")
        obj = parse_document(text)
        if not isinstance(obj.get("friendly_name"), str) or not isinstance(obj.get("tweak_password"), str):
            raise CatalogError("Unexpected APNA profile schema")
        # tweak_password, expiry, HWID and root flags are post-decryption app checks.
        return text.encode("utf-8")
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise CatalogError("Invalid or unsupported APNA profile") from exc


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CatalogError("Fixed source attempted a redirect")


def download() -> bytes:
    request = Request(CATALOG_URL, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"})
    try:
        with build_opener(_NoRedirect()).open(request, timeout=25) as response:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise CatalogError("Invalid remote response")
            data = response.read(MAX_INPUT + 1)
        if not data or len(data) > MAX_INPUT:
            raise CatalogError("Remote response exceeds limits")
        return data
    except OSError as exc:
        raise CatalogError("Unable to download official APNA catalog") from exc


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
    """Read only exact base.apk/assets/janu.json, never execute APK contents."""
    try:
        if path.stat().st_size > MAX_BUNDLE:
            raise CatalogError("Bundle size exceeds limit")
        with zipfile.ZipFile(path) as outer:
            if path.suffix.lower() == ".apk":
                return _member(outer, "assets/janu.json", MAX_INPUT)
            base_apk = _member(outer, "base.apk", MAX_BUNDLE)
        with zipfile.ZipFile(io.BytesIO(base_apk)) as inner:
            return _member(inner, "assets/janu.json", MAX_INPUT)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise CatalogError("Invalid APK/APKS") from exc


def summary(plaintext: bytes) -> dict:
    """Counts only: avoid leaking stored users, passwords or payloads."""
    document = json.loads(plaintext)
    return {
        "provider": "apna-vpn",
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
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--apks", type=Path, help="Read embedded janu.json from APK/APKS")
    src.add_argument("--input", type=Path, help="Read encrypted janu.json")
    src.add_argument("--stdin", action="store_true", help="Read encrypted Base64 on stdin")
    src.add_argument("--file", type=Path, help="Read an exported .apnavpn profile")
    src.add_argument("--text", help="Read an apnavpn:// link")
    parser.add_argument("--summary", action="store_true", help="Print metadata without credentials")
    parser.add_argument("--output", type=Path, help="Write output in a private 0600 file")
    args = parser.parse_args()
    try:
        is_profile = args.file is not None or args.text is not None
        remote = all(item is None for item in (args.apks, args.input, args.file, args.text)) and not args.stdin
        if args.summary and is_profile:
            raise CatalogError("--summary applies to catalogs only")
        if args.apks:
            encrypted = from_apks(args.apks)
        elif args.input or args.file:
            source = args.input or args.file
            if source.stat().st_size > MAX_INPUT:
                raise CatalogError("Input too large")
            encrypted = source.read_bytes()
        elif args.stdin:
            encrypted = sys.stdin.buffer.read(MAX_INPUT + 1)
        elif args.text is not None:
            encrypted = args.text.encode("utf-8")
        else:
            encrypted = download()
        plaintext = decode_profile_bytes(encrypted) if is_profile else decode_json_bytes(encrypted)
        result = (json.dumps(summary(plaintext), ensure_ascii=False, indent=2).encode("utf-8")
                  if args.summary else plaintext)
        output_path = args.output or (Path("apna_vpn_catalogo.json") if remote and not args.summary else None)
        if output_path:
            fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(result + b"\n" if args.summary else result)
            print(f"Guardado: {output_path}")
        else:
            sys.stdout.buffer.write(result + b"\n" if args.summary else result)
        return 0
    except (CatalogError, OSError) as exc:
        print(f"APNA decoder: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
