#!/usr/bin/env python3
"""Reproduce Maya's authenticated URI -> GitHub file -> full offline decode.

No embedded credential. Only run with a token you own and are authorized to use.
Does not print payloads, tokens or private metadata by default.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from decoders.Python._noobcrypt import KEYS, decrypt_profile  # noqa: E402

SOURCE = "https://api.github.com/repos/janatshaban/noob_files/contents/config/mayatun/"
SAMPLE = "maya://iMRXyO/sbosPgEPZ71e2EYFpaAA+q6is2Nc/iVbn3v8BmShW3xpjA+KPZ8g="
MAX_RESPONSE = 8 * 1024 * 1024


def parse_reference(uri: str) -> str:
    if not uri.startswith("maya://") or len(uri) > 512:
        raise ValueError("INVALID_MAYA_REFERENCE")
    encoded = uri[7:]
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", encoded) or len(encoded) % 4:
        raise ValueError("INVALID_MAYA_BASE64")
    data = base64.b64decode(encoded, validate=True)
    if len(data) < 29 or base64.b64encode(data).decode() != encoded:
        raise ValueError("INVALID_MAYA_ENVELOPE")
    clear = ChaCha20Poly1305(KEYS["maya"]).decrypt(data[:12], data[12:], None)
    identifier = clear.decode("utf-8")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", identifier):
        raise ValueError("INVALID_MAYA_IDENTIFIER")
    return identifier


def download(identifier: str, token: str | None) -> bytes:
    url = SOURCE + identifier + ".maya"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "SP-DECODE-Maya-Research/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=20) as response:
        if response.status != 200:
            raise ValueError("UNEXPECTED_GITHUB_STATUS")
        raw = response.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise ValueError("REMOTE_TOO_LARGE")
    metadata = json.loads(raw.decode("utf-8"))
    expected = identifier + ".maya"
    if (metadata.get("type") != "file" or metadata.get("name") != expected
        or metadata.get("path") != "config/mayatun/" + expected
        or metadata.get("encoding") != "base64"):
        raise ValueError("INVALID_GITHUB_METADATA")
    outer = base64.b64decode(metadata["content"], validate=False)
    if len(outer) != metadata.get("size") or len(outer) > 3 * 1024 * 1024:
        raise ValueError("INVALID_GITHUB_SIZE")
    return outer


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uri", default=SAMPLE)
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        identifier = parse_reference(args.uri)
        print("URI_CHACHA20_POLY1305_OK")
        print("FILE_IDENTIFIER_LENGTH", len(identifier))
        if not args.download:
            return 0
        data = download(identifier, os.environ.get("CLOUD_MAYA_GITHUB_TOKEN"))
        value = decrypt_profile(data, "maya")
        print("DOWNLOAD_AND_DECODE_OK", "bytes", len(data),
              "top_level_fields", len(value))
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(value, stream, ensure_ascii=False, indent=2)
        return 0
    except urllib.error.HTTPError as error:
        print("REMOTE_HTTP_STATUS", error.code, file=sys.stderr)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        print("MAYA_REFERENCE_OR_DECODE_FAILED", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
