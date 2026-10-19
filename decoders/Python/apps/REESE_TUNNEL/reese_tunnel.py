#!/usr/bin/env python3
"""Offline REESE TUNNEL .RT reader: RSE5/C3-C4 and legacy RSE1-RSE4.

Source: REESE TUNNEL 3.23.12 (129), ReeseFile and its Java crypto fallback.
Requires PyCryptodome. No Android runtime, native libraries or network calls.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import hashlib
import hmac
import json
import math
import re
import struct
import sys
import zlib
from pathlib import Path
from typing import Any

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

MAGIC = bytes.fromhex("a719d24c")
# SHA-256 of the supplied APK's public signing certificate, not a private key.
APK_SIGNER_SHA256 = "D834BF8D60BFEA09A80A51CCD1A77DE3EF966E7833EBB2D0B8DC1F750E38BBA7"
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_LEGACY_BODY = 2 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 200_000


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _trim(value: str) -> str:
    # Kotlin CharSequence.trim uses Character.isWhitespace/isSpaceChar.
    # Python additionally treats U+0085 as whitespace; Java does not.
    start, end = 0, len(value)
    while start < end and value[start].isspace() and value[start] != "\x85":
        start += 1
    while end > start and value[end - 1].isspace() and value[end - 1] != "\x85":
        end -= 1
    return value[start:end]


def _b64(text: str) -> bytes:
    compact = re.sub(r"[ \t\r\n]", "", text)
    if not compact or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
        raise DecodeError("FORMAT_ERROR", "Invalid standard Base64 input.")
    try:
        return base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
    except (ValueError, binascii.Error):
        raise DecodeError("FORMAT_ERROR", "Invalid standard Base64 input.") from None


def _input(data: bytes | str) -> bytes:
    if not isinstance(data, (bytes, str)) or not data:
        raise DecodeError("FORMAT_ERROR", "Expected a non-empty .RT file or text.")
    if len(data) > MAX_INPUT_BYTES:
        raise DecodeError("SIZE_LIMIT", "Input exceeds 16 MiB.")
    if isinstance(data, bytes) and data.startswith((MAGIC, b"RSE1", b"RSE2", b"RSE3", b"RSE4")):
        return data
    try:
        text = data.decode("utf-8-sig") if isinstance(data, bytes) else data.removeprefix("\ufeff")
        if len(text.encode("utf-8")) > MAX_INPUT_BYTES:
            raise DecodeError("SIZE_LIMIT", "Input exceeds 16 MiB.")
    except UnicodeError:
        raise DecodeError("FORMAT_ERROR", "Unknown binary header or invalid UTF-8 text.") from None
    text = text.strip()
    if text.startswith("{"):
        return text.encode("utf-8")
    # ReeseFile.x: ignore human-readable armor and metadata lines.
    body = "".join(line.strip() for line in text.splitlines()
                   if line.strip() and not line.strip().startswith("-----") and ": " not in line.strip())
    return _b64(body)


def _gcm(key: bytes, nonce: bytes, body: bytes, aad: bytes = b"") -> bytes:
    if len(body) < 16:
        raise DecodeError("TRUNCATED", "Missing GCM authentication tag.")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(aad)
    try:
        return cipher.decrypt_and_verify(body[:-16], body[-16:])
    except ValueError:
        raise DecodeError("AUTH_FAILED", "Authentication failed; check credentials and file integrity.") from None


def _inflate(packed: bytes) -> bytes:
    try:
        inflater = zlib.decompressobj(-15)
        plain = inflater.decompress(packed, MAX_JSON_BYTES + 1)
    except zlib.error:
        raise DecodeError("INVALID_DEFLATE", "Authenticated content is not raw DEFLATE.") from None
    if len(plain) > MAX_JSON_BYTES or inflater.unconsumed_tail:
        raise DecodeError("SIZE_LIMIT", "Decompressed JSON exceeds 32 MiB.")
    if not inflater.eof or inflater.unused_data:
        raise DecodeError("INVALID_DEFLATE", "Truncated DEFLATE stream or unexpected trailing data.")
    return plain


def _unpad_random(body: bytes, *, with_length: bool) -> bytes:
    if not body:
        raise DecodeError("INVALID_PADDING", "Empty authenticated body.")
    offset = body[0] + 17
    if offset > len(body):
        raise DecodeError("INVALID_PADDING", "Invalid random prefix length.")
    if not with_length:
        return body[offset:]
    if offset + 4 > len(body):
        raise DecodeError("INVALID_PADDING", "Missing compressed payload length.")
    size = struct.unpack_from(">i", body, offset)[0]
    offset += 4
    if size <= 0 or size > len(body) - offset:
        raise DecodeError("INVALID_PADDING", "Invalid compressed payload length.")
    return body[offset:offset + size]


def _modern(blob: bytes, hwid: str, password: str, signer: str,
            audit: dict[str, Any]) -> bytes:
    if len(blob) < 5:
        raise DecodeError("TRUNCATED", "Missing RSE5 variant byte.")
    variant = blob[4]
    if variant not in (0xC3, 0xC4):
        raise DecodeError("UNSUPPORTED_VERSION", "Unsupported binary export; expected RSE5 C3 or C4.")
    if len(blob) < 50:
        raise DecodeError("TRUNCATED", "Missing RSE5 header or GCM tag.")
    flags = blob[5]
    if flags & ~(7 if variant == 0xC4 else 1):
        raise DecodeError("UNSUPPORTED_FLAGS", "Unknown protection flags for this RSE5 variant.")
    if flags & 1 and not hwid:
        raise DecodeError("HWID_REQUIRED", "This export requires its original HWID.")
    password_used = variant == 0xC3 or bool(flags & 2)
    if variant == 0xC4 and password_used and not password:
        raise DecodeError("PASSWORD_REQUIRED", "This export requires its export password.")
    signature_used = variant == 0xC4 and bool(flags & 4)
    if signature_used and not re.fullmatch(r"[0-9A-Fa-f]{64}", signer):
        raise DecodeError("SIGNER_REQUIRED", "Expected the exporting APK's public certificate SHA-256.")
    material = "REESE-CUSTOM/RSE5|" + (hwid if flags & 1 else "") + "|" + (password if password_used else "")
    if signature_used:
        material += "|SIG:" + signer.upper()
    key = hashlib.pbkdf2_hmac("sha256", material.encode("utf-8"), blob[6:22], 32768, 32)
    clear = _gcm(key, blob[22:34], blob[34:], blob[:34])
    audit.update(format="RSE5-" + format(variant, "02X"), authenticated=True,
                 flags=flags, signature_bound=signature_used)
    return _inflate(_unpad_random(clear, with_length=True))


def _stream(seed: bytes, size: int) -> bytes:
    return b"".join(hashlib.sha256(seed + struct.pack(">I", n)).digest()
                    for n in range((size + 31) // 32))[:size]


def _unshuffle(body: bytes, seed: bytes) -> bytes:
    indices = list(range(len(body)))
    stream = _stream(seed, len(body) * 4)
    offset = 0
    for index in range(len(body) - 1, 0, -1):
        selected = struct.unpack_from(">I", stream, offset)[0] % (index + 1)
        offset += 4
        indices[index], indices[selected] = indices[selected], indices[index]
    return bytes(body[index] for index in indices)


def _cbc(key: bytes, iv: bytes, body: bytes) -> bytes:
    try:
        return unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(body), 16)
    except ValueError:
        raise DecodeError("INVALID_CBC", "Authenticated legacy CBC layer has invalid padding.") from None


def _legacy(blob: bytes, hwid: str, password: str, audit: dict[str, Any]) -> bytes:
    version = blob[:4]
    header_size = 40 if version == b"RSE4" else 56 if version == b"RSE1" else 72
    tag_size = 16 if version == b"RSE4" else 32
    if len(blob) < header_size + tag_size:
        raise DecodeError("TRUNCATED", "Incomplete legacy header or authentication tag.")
    selector = blob[header_size - 8:header_size - 4]
    if not re.fullmatch(rb"[0-9a-f]{4}", selector):
        raise DecodeError("FORMAT_ERROR", "Invalid legacy HWID selector.")
    if selector != b"0000" and not hwid:
        raise DecodeError("HWID_REQUIRED", "This export requires its original HWID.")
    selected_hwid = hwid if selector != b"0000" else ""
    declared = struct.unpack_from(">i", blob, header_size - 4)[0]
    if declared <= 0:
        raise DecodeError("TRUNCATED", "Invalid legacy body length.")
    if version == b"RSE4":
        material = ("REESE-CUSTOM/RSE4|" + selected_hwid + "|" + password).encode("utf-8")
        key = hashlib.pbkdf2_hmac("sha256", material, blob[4:20], 600000, 32)
        clear = _gcm(key, blob[20:32], blob[40:], blob[:40])
        if declared > len(clear):
            raise DecodeError("TRUNCATED", "Declared legacy body exceeds authenticated length.")
        packed = _unpad_random(clear, with_length=False)
    else:
        if declared > MAX_LEGACY_BODY:
            raise DecodeError("SIZE_LIMIT", "Legacy multi-layer body exceeds 2 MiB.")
        if header_size + declared + 32 != len(blob):
            raise DecodeError("TRUNCATED", "Legacy body length does not match the file.")
        rounds, size = {b"RSE1": (80000, 128), b"RSE2": (140000, 192), b"RSE3": (24000, 192)}[version]
        material = "REESE-CUSTOM/config-envelope/v1|" + selected_hwid
        if password:
            material += "|" + password
        keys = hashlib.pbkdf2_hmac("sha256", material.encode("utf-8"), blob[4:20], rounds, size)
        if not hmac.compare_digest(hmac.digest(keys[96:128], blob[:-32], "sha256"), blob[-32:]):
            raise DecodeError("AUTH_FAILED", "Legacy HMAC failed; check credentials and file integrity.")
        body = blob[header_size:-32]
        if version != b"RSE1":
            body = _cbc(keys[128:160], blob[48:64], _unshuffle(body, keys[160:192]))
        body = bytes(a ^ b for a, b in zip(body, _stream(keys[64:96], len(body))))
        clear = _gcm(keys[:32], blob[20:32], _cbc(keys[32:64], blob[32:48], body))
        packed = _unpad_random(clear, with_length=False) if version != b"RSE1" else clear
    audit.update(format=version.decode("ascii"), authenticated=True, signature_bound=False)
    return _inflate(packed)


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DecodeError("INVALID_JSON", "Duplicate JSON keys are not supported.")
        result[key] = value
    return result


def _constant(value: str) -> Any:
    raise DecodeError("INVALID_JSON", "Non-finite JSON numbers are not supported.")


def _document(raw: bytes) -> dict[str, Any]:
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_constant)
    except (UnicodeError, ValueError, RecursionError):
        raise DecodeError("INVALID_JSON", "Decoded content is not valid UTF-8 JSON.") from None
    if not isinstance(document, dict):
        raise DecodeError("WRONG_DOCUMENT", "Expected a REESE JSON object.")
    if "config" in document or "meta" in document:
        if not isinstance(document.get("config"), dict) or not isinstance(document.get("meta"), dict):
            raise DecodeError("WRONG_DOCUMENT", "Expected both 'meta' and 'config' objects.")
        config = document["config"]
    else:
        config = document
    if not any(key in config for key in ("profileName", "sshHost", "v2rayProfiles", "slowDnsNameserver")):
        raise DecodeError("WRONG_DOCUMENT", "No recognizable REESE configuration fields.")
    if config.get("vault"):
        raise DecodeError("DEVICE_VAULT_REQUIRED", "The profile contains a device-local vault requiring its original Android Keystore.")
    stack = [(document, 0)]
    count = 0
    while stack:
        value, depth = stack.pop()
        count += 1
        if depth > MAX_DEPTH or count > MAX_NODES:
            raise DecodeError("STRUCTURE_LIMIT", "JSON structure exceeds its limits.")
        if isinstance(value, dict):
            stack.extend((v, depth + 1) for v in value.values())
            stack.extend((k, depth + 1) for k in value)
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise DecodeError("INVALID_JSON", "Non-finite JSON number.")
        elif isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeError:
                raise DecodeError("INVALID_JSON", "Invalid Unicode string.") from None
        if count + len(stack) > MAX_NODES:
            raise DecodeError("STRUCTURE_LIMIT", "JSON structure exceeds its limits.")
    return document


def decode(data: bytes | str, *, hwid: str = "", password: str = "",
           signer_sha256: str = APK_SIGNER_SHA256,
           audit: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the original complete JSON, preserving metadata and all fields."""
    for value in (hwid, password, signer_sha256):
        if not isinstance(value, str) or len(value) > 4096:
            raise DecodeError("CREDENTIAL_FORMAT", "Invalid credential type or length.")
    try:
        hwid = _trim(hwid).upper()
        password = _trim(password)
        hwid.encode("utf-8")
        password.encode("utf-8")
    except UnicodeError:
        raise DecodeError("CREDENTIAL_FORMAT", "Invalid credential encoding.") from None
    blob = _input(data)
    info: dict[str, Any] = {}
    if blob.startswith(MAGIC):
        raw = _modern(blob, hwid, password, signer_sha256, info)
    elif blob[:4] in (b"RSE1", b"RSE2", b"RSE3", b"RSE4"):
        raw = _legacy(blob, hwid, password, info)
    elif blob.startswith(b"{"):
        raw = blob
        info.update(format="plain-json", authenticated=False, signature_bound=False)
    else:
        raise DecodeError("UNSUPPORTED_VERSION", "Unrecognized REESE file header.")
    result = _document(raw)
    if info.get("authenticated") and not (isinstance(result.get("meta"), dict) and isinstance(result.get("config"), dict)):
        raise DecodeError("WRONG_DOCUMENT", "Encrypted export must contain a meta/config envelope.")
    if audit is not None:
        audit.update(info)
    return result


def run(file_bytes: bytes | str, **kwargs: Any) -> str | None:
    try:
        return json.dumps(decode(file_bytes, **kwargs), ensure_ascii=False, indent=2) + "\n"
    except DecodeError:
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline REESE TUNNEL .RT decoder (RSE1-RSE5)")
    parser.add_argument("file", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--hwid", default="", help="Original export HWID, when required")
    parser.add_argument("--signer-sha256", default=APK_SIGNER_SHA256, help="Public exporting APK certificate SHA-256")
    credentials = parser.add_mutually_exclusive_group()
    credentials.add_argument("--ask-password", action="store_true", help="Prompt without echo")
    credentials.add_argument("--password-file", type=Path, help="Read the export password from a local UTF-8 file")
    args = parser.parse_args(argv)
    try:
        password = ""
        if args.ask_password:
            password = getpass.getpass("Export password: ")
        elif args.password_file:
            with args.password_file.open("rb") as handle:
                secret = handle.read(4097)
            if len(secret) > 4096:
                raise DecodeError("CREDENTIAL_FORMAT", "Password file exceeds 4096 bytes.")
            try:
                password = secret.decode("utf-8-sig")
            except UnicodeError:
                raise DecodeError("CREDENTIAL_FORMAT", "Password file is not UTF-8.") from None
        with args.file.open("rb") as handle:
            raw = handle.read(MAX_INPUT_BYTES + 1)
        result = json.dumps(decode(raw, hwid=args.hwid, password=password,
                                   signer_sha256=args.signer_sha256), ensure_ascii=False, indent=2) + "\n"
        if args.output:
            args.output.write_text(result, encoding="utf-8")
        else:
            sys.stdout.write(result)
        return 0
    except DecodeError as error:
        print(json.dumps({"error": error.code, "message": str(error)}), file=sys.stderr)
        return 1
    except (OSError, EOFError):
        print(json.dumps({"error": "IO_ERROR", "message": "Cannot read credentials/input or write the result."}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
