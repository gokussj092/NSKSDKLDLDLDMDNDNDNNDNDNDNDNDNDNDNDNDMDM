#!/usr/bin/env python3
"""APNA VPN 3.9 embedded server catalog (Base64 + modified XXTEA).

Standard-library-only, offline. XXTEA does not authenticate ciphertext.
No APK, native SO, external endpoint or Android runtime needed to decode data.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import io
import json
import os
from pathlib import Path
import re
import struct
import sys
import zipfile

MAX_INPUT = 8 * 1024 * 1024
MAX_BUNDLE = 100 * 1024 * 1024
DELTA = 0x9E5729B1  # APNA 3.9 Dalvik LBm.b, NOT the standard XXTEA delta
KEY = b"...|..."  # App-format constant from LBm.a, private worker only
MASK = 0xFFFFFFFF
ROOT_KEYS = ("Free_servers", "Payloads")


class CatalogError(ValueError):
    """Invalid or unsupported APNA catalog."""


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
        parsed = json.loads(plaintext.decode("utf-8"))
        if (not isinstance(parsed, dict) or
                any(not isinstance(parsed.get(section), list) for section in ROOT_KEYS)):
            raise CatalogError("Unexpected APNA catalog schema")
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        if isinstance(exc, CatalogError):
            raise
        raise CatalogError("Unsupported APNA JSON structure") from exc
    return plaintext


def run(data: bytes) -> str:
    """Private worker contract; output is complete unmodified JSON."""
    return decode_json_bytes(data).decode("utf-8")


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
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--apks", type=Path, help="Read embedded janu.json from APK/APKS")
    src.add_argument("--input", type=Path, help="Read encrypted janu.json")
    src.add_argument("--stdin", action="store_true", help="Read encrypted Base64 on stdin")
    parser.add_argument("--summary", action="store_true", help="Print metadata without credentials")
    parser.add_argument("--output", type=Path, help="Write output in a private 0600 file")
    args = parser.parse_args()
    try:
        if args.apks:
            encrypted = from_apks(args.apks)
        elif args.input:
            if args.input.stat().st_size > MAX_INPUT:
                raise CatalogError("Input too large")
            encrypted = args.input.read_bytes()
        else:
            encrypted = sys.stdin.buffer.read(MAX_INPUT + 1)
        plaintext = decode_json_bytes(encrypted)
        result = (json.dumps(summary(plaintext), ensure_ascii=False, indent=2).encode("utf-8")
                  if args.summary else plaintext)
        if args.output:
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(result + b"\n" if args.summary else result)
        else:
            sys.stdout.buffer.write(result + b"\n" if args.summary else result)
        return 0
    except (CatalogError, OSError) as exc:
        print(f"APNA decoder: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
