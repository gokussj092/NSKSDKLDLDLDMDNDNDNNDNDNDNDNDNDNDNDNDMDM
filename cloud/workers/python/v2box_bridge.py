#!/usr/bin/env python3
"""V2Box protected exports: read password only from stdin, no retry of fixed key."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))


def fail(code: str) -> int:
    sys.stdout.write(json.dumps({"workerError": code}))
    return 3


def valid_envelope(raw: bytes) -> dict:
    if not raw or len(raw) > 2 * 1024 * 1024:
        raise ValueError("Invalid V2Box size")
    text = raw.decode("utf-8-sig").strip()
    for prefix in ("v2box://", "locked="):
        if prefix in text:
            text = text.split(prefix, 1)[1]
    try:
        document = json.loads(text)
    except (ValueError, TypeError):
        data = base64.b64decode("".join(text.split()) + "===", validate=True)
        document = json.loads(data)
    if not isinstance(document, dict) or document.get("magic") != "v2box_export":
        raise ValueError("Unsupported V2Box envelope")
    version = document.get("version")
    if type(version) is int and version == 2:
        encoded_header = document.get("header")
        if not isinstance(encoded_header, str) or not 0 < len(encoded_header) <= 4096:
            raise ValueError("Invalid V2Box header")
        try:
            header_raw = base64.b64decode(encoded_header, validate=True)
            header = json.loads(header_raw.decode("utf-8"))
            if not isinstance(header, dict) or header.get("v") != 2 or (
                header.get("kdf") != "pbkdf2-sha256"
            ):
                raise ValueError("Unsupported V2Box KDF")
            iterations = header.get("iterations")
            if type(iterations) is not int or not 100_000 <= iterations <= 1_200_000:
                raise ValueError("Invalid V2Box iterations")
            salt_string = header.get("salt")
            if not isinstance(salt_string, str) or not 16 <= len(
                base64.b64decode(salt_string, validate=True)
            ) <= 32:
                raise ValueError("Invalid V2Box salt")
        except (UnicodeError, ValueError, TypeError):
            raise ValueError("Invalid V2Box header") from None
        protected = True
    elif version is None or (type(version) is int and version == 1):
        if not isinstance(document.get("isPasswordProtected"), bool):
            raise ValueError("Invalid V2Box protection flag")
        protected = document["isPasswordProtected"]
    else:
        raise ValueError("Unsupported V2Box version")
    for key, length in (("nonce", 12), ("tag", 16), ("ciphertext", None)):
        value = document.get(key)
        if not isinstance(value, str) or len(value) > 2 * 1024 * 1024 * 2:
            raise ValueError("Invalid V2Box field")
        decoded = base64.b64decode(value, validate=True)
        if (length is not None and len(decoded) != length) or not decoded:
            raise ValueError("Invalid V2Box field length")
    document["_password_protected"] = protected
    return document


def process(raw: bytes, credentials: dict) -> tuple[str, dict | None]:
    if not isinstance(credentials, dict) or set(credentials) - {"password"}:
        return "INVALID_CREDENTIALS", None
    password = credentials.get("password")
    if password is not None and (not isinstance(password, str) or
                                 not 0 < len(password.encode("utf-8")) <= 4096):
        return "INVALID_CREDENTIALS", None
    try:
        envelope = valid_envelope(raw)
    except (UnicodeError, ValueError, TypeError, KeyError):
        return "DECODE_FAILED", None
    protected = envelope["_password_protected"]
    if protected and password is None:
        return "PASSWORD_REQUIRED", None
    if not protected and password is not None:
        return "INVALID_CREDENTIALS", None
    from decoders.Python.v2box_export import decode_file
    result = decode_file(raw, password=password)
    if result is None or not isinstance(result, dict) or result.get("__need_password__"):
        return ("AUTH_FAILED" if protected else "DECODE_FAILED"), None
    return "OK", result


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    try:
        raw = Path(sys.argv[1]).read_bytes()
        payload = sys.stdin.buffer.read(8193)
        if len(payload) > 8192:
            return fail("INVALID_CREDENTIALS")
        credentials = json.loads(payload) if payload else {}
        code, result = process(raw, credentials)
        if code != "OK":
            return fail(code)
        sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (OSError, UnicodeError, ValueError, TypeError):
        return fail("DECODE_FAILED")


if __name__ == "__main__":
    raise SystemExit(main())
