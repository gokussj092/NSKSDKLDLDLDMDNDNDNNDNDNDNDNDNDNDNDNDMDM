#!/usr/bin/env python3
"""Offline Hex Tunnel / HexVPN .hexcm reader (single and double envelopes).

Requires PyCryptodome. No APK, VM, internet or user password is needed.
The original document, including all lock fields, is returned unchanged.
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
from pathlib import Path

from Crypto.Cipher import AES, ChaCha20_Poly1305

MAX_BYTES = 16 * 1024 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024
PASSWORD = b"JotchuaZDevz105V"  # AppConfig.keydev(), original APK constant.
INNER_KEY = bytes.fromhex(
    "1e7e5f507b01878ca32f4a1a74804e22cb1a4fd91bc4ff93f315474a9c55e8ad"
)


class DecodeError(ValueError):
    """A complete, authenticated configuration could not be recovered."""


def _b64(data: bytes) -> bytes:
    try:
        if not data or len(data) > MAX_BYTES:
            raise DecodeError("Invalid envelope size")
        wire = re.sub(rb"[ \t\r\n]", b"", data)
        return base64.b64decode(wire, validate=True)
    except (ValueError, binascii.Error) as error:
        raise DecodeError("Invalid Base64 envelope") from error


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise DecodeError("Duplicate JSON property")
        result[key] = value
    return result


def _constant(_):
    raise DecodeError("Non-finite JSON number")


def _unsigned_export(text: str) -> bytes:
    """Remove only the root signature from the original exported JSON bytes.

    The app signs its compact JSONObject output before appending signature.
    Keep original number and string lexemes: Python float formatting and JSON
    slash escaping differ from Android. No reordering or field deletion occurs.
    """
    decoder = json.JSONDecoder(object_pairs_hook=_pairs, parse_constant=_constant)
    i = 1
    fragments = []
    while True:
        while text[i].isspace():
            i += 1
        if text[i] == "}":
            break
        start = i
        key, i = decoder.raw_decode(text, i)
        while text[i].isspace():
            i += 1
        if text[i] != ":":
            raise DecodeError("Invalid JSON object")
        i += 1
        while text[i].isspace():
            i += 1
        _, end = decoder.raw_decode(text, i)
        if key != "signature":
            fragments.append(text[start:end])
        i = end
        while text[i].isspace():
            i += 1
        if text[i] == "}":
            break
        if text[i] != ",":
            raise DecodeError("Invalid JSON object")
        i += 1
    return ("{" + ",".join(fragments) + "}").encode("utf-8")


def _document(raw: bytes) -> dict:
    if not raw or len(raw) > MAX_JSON_BYTES:
        raise DecodeError("Invalid plaintext size")
    try:
        text = raw.decode("utf-8").strip()
        doc = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
        pending = [(doc, 0)]
        count = 0
        while pending:
            value, depth = pending.pop()
            count += 1
            if depth > 64 or count > 200_000:
                raise DecodeError("JSON structure exceeds limits")
            if isinstance(value, dict):
                for key, item in value.items():
                    key.encode("utf-8")
                    pending.append((item, depth + 1))
            elif isinstance(value, list):
                pending.extend((item, depth + 1) for item in value)
            elif isinstance(value, str):
                value.encode("utf-8")
            elif isinstance(value, float) and not math.isfinite(value):
                raise DecodeError("Non-finite JSON number")
        if not isinstance(doc, dict):
            raise DecodeError("Expected an exported object")
        if type(doc.get("version")) is not int or doc["version"] != 1:
            raise DecodeError("Unsupported document version")
        if not isinstance(doc.get("server"), dict) or not doc["server"]:
            raise DecodeError("Missing complete server")
        meta = doc.get("meta")
        if not isinstance(meta, dict) or type(meta.get("blocked")) is not bool:
            raise DecodeError("Missing lock metadata")
        signature = doc.get("signature")
        if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{64}", signature):
            raise DecodeError("Missing export signature")
        expected = hashlib.sha256(_unsigned_export(text) + PASSWORD).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise DecodeError("Invalid export signature")
        return doc
    except (UnicodeError, RecursionError, IndexError, TypeError, ValueError) as error:
        raise DecodeError("Invalid signed configuration") from error


def decode_with_method(data: bytes) -> tuple[dict, str]:
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError("Invalid file size")
    raw = _b64(data)
    if len(raw) < 44:
        raise DecodeError("Truncated AES envelope")
    key = hashlib.pbkdf2_hmac("sha256", PASSWORD, raw[:16], 100_000, 32)
    try:
        aes = AES.new(key, AES.MODE_GCM, nonce=raw[16:28])
        plain = aes.decrypt_and_verify(raw[28:-16], raw[-16:])
        if plain.lstrip().startswith(b"{"):
            return _document(plain), "aes256gcm"
        # Current CustomServerShare.doubleDecrypt: AESPRO -> Base64 -> HexVPN.
        inner = _b64(plain)
        if len(inner) < 28:
            raise DecodeError("Truncated native envelope")
        cipher = ChaCha20_Poly1305.new(key=INNER_KEY, nonce=inner[:12])
        decoded = cipher.decrypt_and_verify(inner[12:-16], inner[-16:])
        return _document(decoded), "aes256gcm+chacha20poly1305"
    except (ValueError, KeyError) as error:
        raise DecodeError("Invalid authenticated configuration") from error


def decode_file(data: bytes) -> dict:
    return decode_with_method(data)[0]


def run(data: bytes) -> str:
    document, method = decode_with_method(data)
    return json.dumps({
        "application": "Hex Tunnel / HexVPN", "extension": ".hexcm",
        "method": method, "signatureVerified": True, "config": document,
    }, ensure_ascii=False, indent=2, allow_nan=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", default="-", help=".hexcm file or - for stdin")
    parser.add_argument("--raw", action="store_true", help="Output only the original signed JSON")
    parser.add_argument("--stdin", action="store_true", help="Read the profile from stdin")
    args = parser.parse_args()
    try:
        if args.stdin or args.file == "-":
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            with Path(args.file).open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
        if args.raw:
            output = json.dumps(decode_file(data), ensure_ascii=False, indent=2, allow_nan=False)
        else:
            output = run(data)
        print(output)
        return 0
    except (ValueError, OSError, RecursionError, UnicodeError):
        print("No se pudo verificar el archivo Hex Tunnel completo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
