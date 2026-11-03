#!/usr/bin/env python3
"""HA Tunnel Plus 1.7.1: complete catalog reader and fixed original GET."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

SOURCE = "https://www.hatunnel.me/resources/main.txt"
USER_AGENT = "Dalvik/2.1.0"
MAX_BYTES = 8 * 1024 * 1024
METHOD_KEY = hashlib.sha1(b"3A0183FADC903782").digest()[:16]


class CatalogError(ValueError):
    """Public error code without source data or credentials."""


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CatalogError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _nonfinite(_):
    raise CatalogError("NONFINITE_JSON")


def _json(data, *, android_controls=False):
    try:
        # The real updater contains a literal LF inside the methods string.
        # Android JSONTokener accepts it. Preserve the resulting string value;
        # this is not a regex repair that could alter profile contents.
        return json.loads(data, strict=not android_controls,
                          object_pairs_hook=_unique, parse_constant=_nonfinite)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise CatalogError("INVALID_CATALOG_JSON") from error


def _section(value, *, list_data):
    if isinstance(value, str):
        value = _json(value)
    if (not isinstance(value, dict) or not isinstance(value.get("version"), str) or not value["version"]
            or not isinstance(value.get("data"), list if list_data else dict)):
        raise CatalogError("INCOMPLETE_CATALOG")
    if list_data:
        if not value["data"] or any(not isinstance(row, dict) for row in value["data"]):
            raise CatalogError("INCOMPLETE_CATALOG")
    elif any(not isinstance(group, list) or any(not isinstance(app, dict) for app in group)
             for group in value["data"].values()):
        raise CatalogError("INCOMPLETE_CATALOG")
    return value


def _methods(value):
    value = _section(value, list_data=True)
    if any(not isinstance(row.get("conf"), dict) for row in value["data"]):
        raise CatalogError("INCOMPLETE_CATALOG")
    return value


def decode_catalog(data: bytes) -> dict:
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_BYTES:
        raise CatalogError("INVALID_CATALOG_SIZE")
    document = _json(data, android_controls=True)
    if not isinstance(document, dict) or not {"servers", "methods", "allowed_apps"} <= document.keys():
        raise CatalogError("INCOMPLETE_CATALOG")
    document["servers"] = _section(document["servers"], list_data=True)
    document["allowed_apps"] = _section(document["allowed_apps"], list_data=False)
    encrypted = document["methods"]
    if not isinstance(encrypted, str):
        raise CatalogError("INVALID_METHODS_ENVELOPE")
    try:
        compact = "".join(encrypted.split())
        ciphertext = base64.b64decode(compact, validate=True)
        if not ciphertext or len(ciphertext) % 16:
            raise CatalogError("INVALID_METHODS_ENVELOPE")
        plain = unpad(AES.new(METHOD_KEY, AES.MODE_ECB).decrypt(ciphertext), 16)
    except (ValueError, UnicodeError) as error:
        raise CatalogError("INVALID_METHODS_ENVELOPE") from error
    document["methods"] = _methods(_json(plain))
    return document


def render(value) -> str:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, indent=2) + "\n"


def run(data: bytes) -> str:
    return render(decode_catalog(data))


def embedded(apk: Path) -> dict:
    result = {}
    with zipfile.ZipFile(apk) as archive:
        for name in ("servers", "methods", "allowed_apps", "customs", "whatsnew"):
            paths = [p for p in (f"assets/resources/{name}.json", f"resources/{name}.json") if p in archive.namelist()]
            if len(paths) != 1 or archive.getinfo(paths[0]).file_size > MAX_BYTES:
                raise CatalogError("INVALID_EMBEDDED_RESOURCE")
            result[name] = _json(archive.read(paths[0]))
    for name in ("servers", "methods", "allowed_apps"):
        result[name] = _section(result[name], list_data=name != "allowed_apps")
    result["methods"] = _methods(result["methods"])
    return result


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise CatalogError("REMOTE_REDIRECT_REJECTED")


def download() -> bytes:
    request = Request(SOURCE, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"})
    try:
        with build_opener(_NoRedirect()).open(request, timeout=25) as response:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise CatalogError("INVALID_REMOTE_RESPONSE")
            data = response.read(MAX_BYTES + 1)
    except OSError as error:
        raise CatalogError("REMOTE_UNAVAILABLE") from error
    if not 0 < len(data) <= MAX_BYTES:
        raise CatalogError("INVALID_CATALOG_SIZE")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", help="Response file or - for stdin; omitted: official fixed GET")
    parser.add_argument("--apk", type=Path, help="Read the five included JSON resources of the supplied unpacked APK")
    parser.add_argument("-o", "--output", type=Path, help="New JSON file, mode 0600; never overwrite")
    args = parser.parse_args()
    try:
        if args.apk:
            if args.file:
                raise CatalogError("CONFLICTING_INPUT")
            result = embedded(args.apk)
        else:
            if args.file == "-":
                data = sys.stdin.buffer.read(MAX_BYTES + 1)
            elif args.file:
                with Path(args.file).open("rb") as stream:
                    data = stream.read(MAX_BYTES + 1)
            else:
                data = download()
            result = decode_catalog(data)
        text = render(result)
        if args.output:
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(text)
        else:
            sys.stdout.write(text)
        return 0
    except (ValueError, OSError, zipfile.BadZipFile, RecursionError):
        print("No se pudo obtener el catálogo completo de HA Tunnel Plus.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
