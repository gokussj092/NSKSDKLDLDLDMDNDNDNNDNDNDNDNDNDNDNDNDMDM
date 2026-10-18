#!/usr/bin/env python3
"""KSH VPN 1.3.2 encrypted server catalog decoder for SP-DECODE.

Local decoding requires only PyCryptodome. Network access is opt-in via --url.
The APK's catalog key is public format material, not an account credential.
"""
from __future__ import annotations

import argparse
import base64
import binascii
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

MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 200_000
CATALOG_URL = "https://raw.githubusercontent.com/yannaing86tt/ksh_server/main/servers.json"
CATALOG_KEY = base64.b64decode("zh+01419+zsCmfiYy1L2hbdMLBoA/2mWeYHuq212xSk=")
NONCE_BYTES = 12
TAG_BYTES = 16


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DecodeError("INVALID_JSON", "Duplicate JSON keys are not supported.")
        result[key] = value
    return result


def _invalid_constant(value: str) -> Any:
    raise DecodeError("INVALID_JSON", "Non-finite JSON numbers are not supported.")


def _load_json(text: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_unique_object,
                          parse_constant=_invalid_constant)
    except (ValueError, RecursionError):
        raise DecodeError("INVALID_JSON", "Expected valid JSON without duplicate keys.") from None


def _text(data: bytes | str) -> str:
    if not isinstance(data, (bytes, str)):
        raise DecodeError("FORMAT_ERROR", "Expected bytes or UTF-8 text.")
    if len(data) > MAX_INPUT_BYTES:
        raise DecodeError("SIZE_LIMIT", "Input exceeds 16 MiB.")
    try:
        text = data.decode("utf-8-sig") if isinstance(data, bytes) else data.removeprefix("\ufeff")
        if len(text.encode("utf-8")) > MAX_INPUT_BYTES:
            raise DecodeError("SIZE_LIMIT", "Input exceeds 16 MiB.")
    except UnicodeError:
        raise DecodeError("FORMAT_ERROR", "Input is not valid UTF-8.") from None
    text = text.strip()
    if not text:
        raise DecodeError("FORMAT_ERROR", "The encrypted catalog is empty.")
    return text


def _blob(data: bytes | str) -> bytes:
    text = _text(data)
    if text.startswith("{"):
        envelope = _load_json(text)
        text = envelope.get("enc")
        if not isinstance(text, str) or not text:
            raise DecodeError("FORMAT_ERROR", "Expected a non-empty 'enc' string.")
    text = re.sub(r"[ \t\r\n]", "", text)
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text):
        raise DecodeError("FORMAT_ERROR", "Invalid standard Base64 catalog.")
    try:
        blob = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise DecodeError("FORMAT_ERROR", "Invalid standard Base64 catalog.") from None
    if len(blob) < NONCE_BYTES + TAG_BYTES:
        raise DecodeError("TRUNCATED", "Catalog is missing its nonce or authentication tag.")
    return blob


def _validate_document(document: Any) -> dict[str, Any]:
    if (not isinstance(document, dict)
            or not isinstance(document.get("servers"), list)
            or any(not isinstance(server, dict) for server in document["servers"])):
        raise DecodeError("WRONG_DOCUMENT", "Expected a catalog with a 'servers' array of objects.")
    stack = [(document, 0)]
    count = 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if depth > MAX_DEPTH or count > MAX_NODES:
            raise DecodeError("STRUCTURE_LIMIT", "Decoded JSON structure exceeds its limits.")
        if isinstance(node, dict):
            stack.extend((key, depth + 1) for key in node)
            stack.extend((value, depth + 1) for value in node.values())
        elif isinstance(node, list):
            stack.extend((value, depth + 1) for value in node)
        elif isinstance(node, float) and not math.isfinite(node):
            raise DecodeError("INVALID_JSON", "JSON number is outside the finite range.")
        elif isinstance(node, str):
            try:
                node.encode("utf-8")
            except UnicodeError:
                raise DecodeError("INVALID_JSON", "JSON contains an invalid Unicode string.") from None
        if count + len(stack) > MAX_NODES:
            raise DecodeError("STRUCTURE_LIMIT", "Decoded JSON structure exceeds its limits.")
    return document


def decode(data: bytes | str) -> dict[str, Any]:
    """Authenticate AES-256-GCM, then return the complete server catalog.

    Accepts the original JSON {"enc": "..."} or its Base64 value alone.
    Raises DecodeError; never returns unauthenticated or partial plaintext.
    """
    blob = _blob(data)
    cipher = AES.new(CATALOG_KEY, AES.MODE_GCM, nonce=blob[:NONCE_BYTES], mac_len=TAG_BYTES)
    try:
        plain = cipher.decrypt_and_verify(blob[NONCE_BYTES:-TAG_BYTES], blob[-TAG_BYTES:])
    except ValueError:
        raise DecodeError("AUTH_FAILED", "KSH catalog authentication failed.") from None
    try:
        text = plain.decode("utf-8")
    except UnicodeError:
        raise DecodeError("INVALID_PLAINTEXT", "Authenticated catalog is not UTF-8.") from None
    return _validate_document(_load_json(text))


def run(file_bytes: bytes | str) -> str | None:
    """SP-DECODE reusable contract: complete JSON on success, None on failure."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2) + "\n"
    except DecodeError:
        return None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_catalog(url: str) -> bytes:
    """Explicit CLI download only; no authentication or VPN connections."""
    try:
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname
                or parsed.username is not None or parsed.password is not None or parsed.fragment):
            raise ValueError
        request = Request(url, headers={"Accept": "application/json", "User-Agent": "SP-DECODE-KSH/1.0"})
        with build_opener(_NoRedirect()).open(request, timeout=20) as response:
            data = response.read(MAX_INPUT_BYTES + 1)
    except (OSError, ValueError, HTTPError, URLError, HTTPException):
        raise DecodeError("DOWNLOAD_FAILED", "Cannot download the HTTPS catalog; redirects are not followed.") from None
    if len(data) > MAX_INPUT_BYTES:
        raise DecodeError("SIZE_LIMIT", "Downloaded catalog exceeds 16 MiB.")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decode KSH VPN 1.3.2 encrypted server catalogs.")
    parser.add_argument("file", nargs="?", type=Path, help="Local encrypted JSON or Base64 file")
    parser.add_argument("--url", nargs="?", const=CATALOG_URL, help="Explicit HTTPS download (default: APK's public catalog)")
    parser.add_argument("-o", "--output", type=Path, help="Write complete JSON to this file")
    args = parser.parse_args(argv)
    if (args.file is None) == (args.url is None):
        parser.error("provide either a local file or --url")
    try:
        if args.file is not None:
            with args.file.open("rb") as handle:
                raw = handle.read(MAX_INPUT_BYTES + 1)
        else:
            raw = fetch_catalog(args.url)
        result = json.dumps(decode(raw), ensure_ascii=False, indent=2) + "\n"
        if args.output is not None:
            args.output.write_text(result, encoding="utf-8")
        else:
            sys.stdout.write(result)
        return 0
    except DecodeError as error:
        print(json.dumps({"error": error.code, "message": str(error)}), file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR", "message": "Cannot read or write the file."}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
