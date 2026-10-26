#!/usr/bin/env python3
"""BD NET VPN PrinceBuild111: catálogo, archivos y texto, solo biblioteca estándar.

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
DELTA = 0x9E5729B1  # BD NET nm.b; same recovered primitive as APNA/HX.
KEY = b"...|..."  # Fixed catalog-format constant from nm.a.
PROFILE_KEY = b"4%PdXch>fkP]"  # Original ARM64 xorWithKey, twelve bytes.
PROFILE_PREFIX = "bdnet://"
CATALOG_URL = "https://raw.githubusercontent.com/panigbatanc/BDNET2023/main/JSONDEC2025"
USER_AGENT = "BD NET VPN/PrinceBuild111"  # Broker identifier; not an APK-derived header.
MASK = 0xFFFFFFFF
ROOT_KEYS = ("Free_servers", "Payloads")
PROTECTED_FIELDS = frozenset({"payload", "host", "sausage", "server_host", "HopPayload",
                              "DualConnectPayload", "SSLPayload", "CustomCert"})
BINARY_FIELDS_KEY = "_spdecodeBinaryFields"


class CatalogError(ValueError):
    """Invalid or unsupported BD NET catalog."""


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
    """Decrypt BD NET's little-endian XXTEA envelope with last-word length."""
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


def decode_outer_bytes(data: bytes) -> bytes:
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
            raise CatalogError("Unexpected BD NET catalog schema")
        for group in ("Free_servers", "Premium_servers", "Vip_servers", "Private_servers", "Payloads"):
            if group in parsed and (not isinstance(parsed[group], list) or
                    any(not isinstance(item, dict) for item in parsed[group])):
                raise CatalogError("Unexpected BD NET catalog records")
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        if isinstance(exc, CatalogError):
            raise
        raise CatalogError("Unsupported BD NET JSON structure") from exc
    return plaintext


def run(data: bytes) -> str:
    """Catalog worker contract; preserve every field and open its nested values."""
    return decode_json_bytes(data).decode("utf-8")


def modified_utf8(data: bytes) -> str:
    """JNI code units, including overlong two/three-byte forms used by this catalog.

    Like JDK readUTF, decode validated continuation bytes to UTF-16 units;
    combine surrogate pairs. Ordinary four-byte UTF-8 stays compatible with
    older XOR-family inputs. Preserve literal NULs in stored fields instead
    of truncating at a C-string terminator. No byte is dropped or replaced.
    """
    units = []
    index = 0
    while index < len(data):
        first = data[index]
        index += 1
        if first < 0x80:
            units.append(first)
            continue
        if first & 0xE0 == 0xC0:
            following, value = 1, first & 0x1F
        elif first & 0xF0 == 0xE0:
            following, value = 2, first & 0x0F
        elif first & 0xF8 == 0xF0:
            following, value = 3, first & 0x07
        else:
            raise CatalogError("Invalid JNI leading byte")
        for _ in range(following):
            if index >= len(data) or data[index] & 0xC0 != 0x80:
                raise CatalogError("Invalid JNI continuation")
            value = (value << 6) | (data[index] & 0x3F)
            index += 1
        if following == 3:
            if not 0x10000 <= value <= 0x10FFFF:
                raise CatalogError("Invalid UTF-8 scalar")
            value -= 0x10000
            units.extend((0xD800 + (value >> 10), 0xDC00 + (value & 0x3FF)))
        else:
            units.append(value)
    try:
        return b"".join(unit.to_bytes(2, "little") for unit in units).decode("utf-16-le")
    except UnicodeError as exc:
        raise CatalogError("Unpaired JNI surrogate") from exc


def xor_bytes(token: str) -> bytes:
    if not token or len(token) > MAX_INPUT or len(token) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", token):
        raise CatalogError("Invalid BD NET hexadecimal")
    raw = bytes.fromhex(token)
    return bytes(value ^ PROFILE_KEY[i % len(PROFILE_KEY)] for i, value in enumerate(raw))


def open_hex(token: str) -> str:
    return modified_utf8(xor_bytes(token))


def decode_fields(obj):
    if BINARY_FIELDS_KEY in obj:
        raise CatalogError("Reserved recovery field already present")
    cache = {}
    binary = []
    nodes = 0
    def walk(value, key="", depth=0, path=""):
        nonlocal nodes
        nodes += 1
        if depth > 64 or nodes > 200000:
            raise CatalogError("JSON structure exceeds limits")
        if isinstance(value, dict):
            return {key: walk(item, key, depth+1, path+"/"+key.replace("~", "~0").replace("/", "~1"))
                    for key, item in value.items()}
        if isinstance(value, list):
            return [walk(item, "", depth+1, path+"/"+str(index)) for index, item in enumerate(value)]
        if isinstance(value, str) and key in PROTECTED_FIELDS and value and len(value) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", value):
            if value not in cache:
                if len(cache) >= 8192:
                    raise CatalogError("Encrypted field limit exceeded")
                raw = xor_bytes(value)
                try:
                    cache[value] = (modified_utf8(raw), None)
                except CatalogError:
                    if b"\0" not in raw:
                        raise
                    # NewStringUTF consumes the C-string prefix. Keep its binary
                    # tail losslessly instead of dropping bytes with errors=ignore.
                    prefix = modified_utf8(raw.split(b"\0", 1)[0])
                    cache[value] = (prefix, {"reason": "NON_UTF8_AFTER_NUL", "encoding": "base64",
                                            "decodedBytesBase64": base64.b64encode(raw).decode("ascii"),
                                            "sourceHex": value})
            text, recovery = cache[value]
            if recovery is not None:
                binary.append({"path": path, **recovery})
            return text
        return value
    result = walk(obj)
    if binary:
        result[BINARY_FIELDS_KEY] = binary
    return result


def render(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, indent=2, allow_nan=False).encode("utf-8")


def decode_json_bytes(data: bytes) -> bytes:
    """Whole catalog, including encrypted server/payload/global fields."""
    return render(decode_fields(parse_document(decode_outer_bytes(data).decode("utf-8"))))


def decode_profile_bytes(data: bytes) -> bytes:
    """Hex -> fixed XOR -> JNI modified UTF-8 -> complete JSON, no password input."""
    if not isinstance(data, bytes) or not data or len(data) > MAX_INPUT:
        raise CatalogError("Invalid profile input size")
    try:
        token = data.decode("utf-8-sig").strip()
        if token.lower().startswith(PROFILE_PREFIX):
            token = token[len(PROFILE_PREFIX):]
        obj = parse_document(open_hex(token))
        # Older .bdnet JSON objects lack tweak metadata; retain that compatibility.
        for key in ("friendly_name", "tweak_password"):
            if key in obj and not isinstance(obj[key], str):
                raise CatalogError("Unexpected BD NET profile schema")
        # tweak_password, expiry, HWID and root flags are post-decryption app checks.
        return render(decode_fields(obj))
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise CatalogError("Invalid or unsupported BD NET profile") from exc


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
        raise CatalogError("Unable to download official BD NET catalog") from exc


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
    """Read only exact base.apk/assets/gunny.json, never execute APK contents."""
    try:
        if path.stat().st_size > MAX_BUNDLE:
            raise CatalogError("Bundle size exceeds limit")
        with zipfile.ZipFile(path) as outer:
            if path.suffix.lower() == ".apk":
                return _member(outer, "assets/gunny.json", MAX_INPUT)
            base_apk = _member(outer, "base.apk", MAX_BUNDLE)
        with zipfile.ZipFile(io.BytesIO(base_apk)) as inner:
            return _member(inner, "assets/gunny.json", MAX_INPUT)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise CatalogError("Invalid APK/APKS") from exc


def summary(plaintext: bytes) -> dict:
    """Counts only: avoid leaking stored users, passwords or payloads."""
    document = json.loads(plaintext)
    return {
        "provider": "bd-net-vpn",
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
        "binaryFieldsPreserved": len(document.get(BINARY_FIELDS_KEY, [])),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--apks", type=Path, help="Read embedded gunny.json from APK/APKS")
    src.add_argument("--input", type=Path, help="Read encrypted gunny.json")
    src.add_argument("--stdin", action="store_true", help="Read encrypted Base64 on stdin")
    src.add_argument("--file", type=Path, help="Read an exported .bdnet profile")
    src.add_argument("--text", help="Read an bdnet:// link")
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
        output_path = args.output or (Path("bd_net_catalogo.json") if remote and not args.summary else None)
        if output_path:
            fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(result + b"\n" if args.summary else result)
            print(f"Guardado: {output_path}")
        else:
            sys.stdout.buffer.write(result + b"\n" if args.summary else result)
        return 0
    except (CatalogError, OSError) as exc:
        print(f"BD NET decoder: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
