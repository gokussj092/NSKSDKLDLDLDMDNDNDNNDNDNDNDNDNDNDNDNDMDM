#!/usr/bin/env python3
"""VPN PLUS PERÚ (com.akunt.vpn 1.0): legacy, AKN2 and AKN3 JSON reader.

This APK has .gol import/export, not an identified remote catalog endpoint.
Use a local file or explicitly supply --url; no APK is needed at runtime.
Requires PyCryptodome. Embedded client constants are public format material.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import math
import re
import sys
from http.client import HTTPException
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 500_000
LEGACY_PASSWORD = b"AkuntVPN@2024#SecretKey$v1"
LEGACY_SALT = b"AkuntVPN_Salt_2024_Fixed_0001"
V2_BASE = bytes.fromhex("416b756e7456706e5f5375703372234b33795f323032362476325f53683464307721416b6e74")
# Preserve the APK's signed-byte rotation results, including non-ASCII bytes.
V3_BASE = bytes.fromhex("a1ab75ae745670ae5f5375703372234b33795f323032362476325f53e834e4307721416b6e745839247051")
V3_SUFFIX = b"AkuntVPN_v3_fixed_salt_2026_secure_key"


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _text(data: bytes | str) -> str:
    if not isinstance(data, (bytes, str)):
        raise DecodeError("FORMAT_ERROR", "Expected bytes or UTF-8 text.")
    if len(data) > MAX_INPUT_BYTES:
        raise DecodeError("SIZE_LIMIT", "Input exceeds 32 MiB.")
    try:
        text = data.decode("utf-8-sig") if isinstance(data, bytes) else data.removeprefix("\ufeff")
        if len(text.encode("utf-8")) > MAX_INPUT_BYTES:
            raise DecodeError("SIZE_LIMIT", "Input exceeds 32 MiB.")
    except UnicodeError:
        raise DecodeError("FORMAT_ERROR", "Expected valid UTF-8 input.") from None
    text = text.strip()
    if not text:
        raise DecodeError("FORMAT_ERROR", "The input is empty.")
    return text


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _constant(value: str) -> Any:
    raise ValueError("Non-finite JSON number")


def _document(text: str) -> dict[str, Any]:
    try:
        document = json.loads(text, object_pairs_hook=_unique, parse_constant=_constant)
    except (ValueError, RecursionError):
        raise DecodeError("INVALID_JSON", "Expected JSON without duplicate keys or non-finite numbers.") from None
    if not isinstance(document, dict):
        raise DecodeError("WRONG_DOCUMENT", "The APK imports a JSON object.")
    stack = [(document, 0)]
    count = 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if depth > MAX_DEPTH or count + len(stack) > MAX_NODES:
            raise DecodeError("STRUCTURE_LIMIT", "JSON structure exceeds its limits.")
        if isinstance(node, dict):
            stack.extend((key, depth + 1) for key in node)
            stack.extend((value, depth + 1) for value in node.values())
        elif isinstance(node, list):
            stack.extend((value, depth + 1) for value in node)
        elif isinstance(node, float) and not math.isfinite(node):
            raise DecodeError("INVALID_JSON", "JSON contains a non-finite number.")
        elif isinstance(node, str):
            try:
                node.encode("utf-8")
            except UnicodeError:
                raise DecodeError("INVALID_JSON", "JSON contains invalid Unicode.") from None
    return document


def _password(version: int) -> bytes:
    if version == 2:
        material = V2_BASE
    else:
        material = V3_BASE + hashlib.sha256(V3_BASE + V3_SUFFIX).digest()
    # Java: new String(material, "ISO-8859-1").toCharArray() -> PBEKeySpec.
    # JCE PBKDF2 encodes these characters as UTF-8, not the original bytes.
    return material.decode("latin-1").encode("utf-8")


def decode(data: bytes | str) -> dict[str, Any]:
    """Return the complete JSON object; never fetch or connect to a VPN.

    AKN2/3 verify HMAC before CBC decryption. Legacy CBC and plain JSON have
    no cryptographic authenticity. No fields or import-policy flags are removed.
    """
    text = _text(data)
    if text.startswith("{"):
        return _document(text)
    version = 1
    if text.startswith(("AKN2:", "AKN3:")):
        version = int(text[3])
        text = text[5:]
    elif re.match(r"AKN\d+:", text):
        raise DecodeError("UNSUPPORTED_VERSION", "Unsupported AKN prefix.")
    text = re.sub(r"[ \t\r\n]", "", text)
    try:
        if not text:
            raise ValueError
        blob = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error):
        raise DecodeError("FORMAT_ERROR", "Expected standard Base64, AKN2: or AKN3:.") from None
    if version == 1:
        if len(blob) < 32 or (len(blob) - 16) % 16:
            raise DecodeError("TRUNCATED", "Invalid legacy IV/ciphertext length.")
        iv, ciphertext = blob[:16], blob[16:]
        key = hashlib.pbkdf2_hmac("sha1", LEGACY_PASSWORD, LEGACY_SALT, 1000, 32)
    else:
        if len(blob) < 80 or (len(blob) - 64) % 16:
            raise DecodeError("TRUNCATED", "Invalid salt/IV/ciphertext/HMAC length.")
        salt, iv, ciphertext, tag = blob[:16], blob[16:32], blob[32:-32], blob[-32:]
        key = hashlib.pbkdf2_hmac("sha256", _password(version), salt,
                                 12000 if version == 2 else 15000, 32)
        if not hmac.compare_digest(hmac.digest(key, blob[:-32], "sha256"), tag):
            raise DecodeError("AUTH_FAILED", "AKN HMAC verification failed.")
    try:
        plain = unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ciphertext), 16)
        decoded = plain.decode("utf-8")
    except (ValueError, UnicodeError):
        raise DecodeError("DECRYPT_FAILED", "Invalid CBC padding or UTF-8 plaintext.") from None
    return _document(decoded)


def run(file_bytes: bytes | str) -> str | None:
    """SP-DECODE contract: complete JSON on success, None on invalid input."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2) + "\n"
    except DecodeError:
        return None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_catalog(url: str) -> bytes:
    """GET an explicitly supplied HTTPS location; no embedded catalog URL exists."""
    try:
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.fragment
                or parsed.username is not None or parsed.password is not None):
            raise ValueError
        request = Request(url, headers={"Accept": "application/json, text/plain, application/octet-stream",
                                        "User-Agent": "SP-DECODE-VPNPlusPeru/1.0"})
        with build_opener(_NoRedirect()).open(request, timeout=20) as response:
            data = response.read(MAX_INPUT_BYTES + 1)
    except (OSError, ValueError, HTTPError, URLError, HTTPException):
        raise DecodeError("DOWNLOAD_FAILED", "Cannot download the HTTPS input; redirects are not followed.") from None
    if len(data) > MAX_INPUT_BYTES:
        raise DecodeError("SIZE_LIMIT", "Downloaded input exceeds 32 MiB.")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decode VPN PLUS PERÚ .gol (legacy/AKN2/AKN3) or JSON. This APK has no identified catalog URL.")
    parser.add_argument("file", nargs="?", type=Path, help="Local encrypted .gol or JSON")
    parser.add_argument("--url", metavar="HTTPS_URL", help="Download from this explicit HTTPS URL (no default endpoint)")
    parser.add_argument("-o", "--output", type=Path, help="Save complete JSON instead of printing it")
    args = parser.parse_args(argv)
    if (args.file is None) == (args.url is None):
        parser.error("provide a local file or --url HTTPS_URL; no catalog endpoint was found in this APK")
    try:
        if args.file is None:
            raw = fetch_catalog(args.url)
        else:
            with args.file.open("rb") as handle:
                raw = handle.read(MAX_INPUT_BYTES + 1)
        result = json.dumps(decode(raw), ensure_ascii=False, indent=2) + "\n"
        if args.output is None:
            sys.stdout.write(result)
        else:
            args.output.write_text(result, encoding="utf-8")
        return 0
    except DecodeError as error:
        print(json.dumps({"error": error.code, "message": str(error)}), file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR", "message": "Cannot read or write the file."}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
