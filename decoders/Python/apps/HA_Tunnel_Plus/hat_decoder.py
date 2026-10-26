#!/usr/bin/env python3
"""Complete historical HA Tunnel .hat reader, also runnable in Termux.

Requires pycryptodome. Does not execute input or contact any network service.
Use --raw-fields to retain encoded profilev5 values for forensic comparison.
"""
from __future__ import annotations
import argparse
import base64
import binascii
import json
import os
from pathlib import Path
import re
import sys

MAX_INPUT_BYTES = 12 * 1024 * 1024
KEY = base64.b64decode("zbNkuNCGSLivpEuep3BcNA==")
XOR_KEY = "**rVg7EkL~c2" + chr(96) + "D[aNn"
PROFILE_FIELDS = ("connection_mode", "custom_payload", "custom_sni", "custom_host")
_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\Z")


class HatError(ValueError):
    """A safe error code; never contains input, plaintext or credentials."""


def _base64(value: str) -> bytes:
    carrier = "".join(value.split())
    if not carrier or not _BASE64.fullmatch(carrier):
        raise HatError("INVALID_BASE64")
    try:
        decoded = base64.b64decode(carrier, validate=True)
    except (ValueError, binascii.Error) as error:
        raise HatError("INVALID_BASE64") from error
    if base64.b64encode(decoded).decode("ascii") != carrier:
        raise HatError("INVALID_BASE64")
    return decoded


def xor_java(value: str, key: str = XOR_KEY) -> str:
    """Java/JavaScript char XOR cycles UTF-16 units, including surrogate pairs."""
    if not key:
        raise HatError("INVALID_XOR_KEY")
    units = value.encode("utf-16-le", "surrogatepass")
    key_bytes = key.encode("utf-16-le", "surrogatepass")
    out = bytearray(len(units))
    for index in range(0, len(units), 2):
        offset = index % len(key_bytes)
        out[index] = units[index] ^ key_bytes[offset]
        out[index + 1] = units[index + 1] ^ key_bytes[offset + 1]
    return out.decode("utf-16-le", "surrogatepass")


def decode_profile_field(value):
    if not isinstance(value, str) or not value:
        return value
    try:
        plain = xor_java(_base64(value).decode("utf-8"))
    except (HatError, UnicodeError):
        return value
    # Match the existing complete Cloud reader. Keep null/plain/unknown fields.
    if any(ord(char) < 9 or 14 <= ord(char) <= 31 for char in plain):
        return value
    return plain


def decode_hat(data: bytes, *, decode_fields: bool = True) -> dict:
    if not isinstance(data, bytes) or not data:
        raise HatError("INVALID_INPUT")
    if len(data) > MAX_INPUT_BYTES:
        raise HatError("INPUT_TOO_LARGE")
    try:
        ciphertext = _base64(data.decode("utf-8-sig"))
    except UnicodeError as error:
        raise HatError("INVALID_BASE64") from error
    if not ciphertext or len(ciphertext) % 16:
        raise HatError("INVALID_ENVELOPE")
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        plaintext = unpad(AES.new(KEY, AES.MODE_ECB).decrypt(ciphertext), 16)
        def invalid_constant(_value):
            raise HatError("INVALID_CONFIG")
        parsed = json.loads(plaintext.decode("utf-8"), parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise HatError("INVALID_CONFIG") from error
    if not isinstance(parsed, dict):
        raise HatError("INVALID_CONFIG")
    profile = parsed.get("profilev5")
    if decode_fields and isinstance(profile, dict):
        for name in PROFILE_FIELDS:
            if name in profile:
                profile[name] = decode_profile_field(profile[name])
    # Password/HWID/expiry flags are metadata, not alternative AES keys.
    # ECB has no authentication tag; successful parsing is not authenticity.
    return parsed


def run(data: bytes) -> str:
    return json.dumps(decode_hat(data), ensure_ascii=True, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help=".hat file, or - for stdin")
    parser.add_argument("-o", "--output", type=Path, help="new JSON output file (mode 0600)")
    parser.add_argument("--raw-fields", action="store_true")
    args = parser.parse_args()
    try:
        if args.input == "-":
            data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        else:
            with Path(args.input).open("rb") as handle:
                data = handle.read(MAX_INPUT_BYTES + 1)
        rendered = json.dumps(decode_hat(data, decode_fields=not args.raw_fields),
                              ensure_ascii=True, indent=2) + "\n"
        if args.output:
            # Refuse overwriting files, including symlinks. Never truncate input.
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(rendered)
        else:
            sys.stdout.write(rendered)
        return 0
    except ImportError:
        print("DEPENDENCY_MISSING: install pycryptodome", file=sys.stderr)
    except HatError as error:
        print(str(error), file=sys.stderr)
    except (OSError, UnicodeError):
        print("FILE_ERROR", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
