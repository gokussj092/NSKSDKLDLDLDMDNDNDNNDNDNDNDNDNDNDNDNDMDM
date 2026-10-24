#!/usr/bin/env python3
"""Ultra Custom 5.2 (hz.custom.vpn): .ua files, ua:// links and bundles.

Offline standalone reader. Password-protected UAP1 profiles require the
original password. No APK, native library, Android runtime or network needed.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import hashlib
import json
import math
import re
import sys
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path
from typing import Any

from Crypto.Cipher import AES

MAX_BYTES = 16 * 1024 * 1024
MAX_TOTAL_XML_BYTES = 32 * 1024 * 1024
MAX_PROFILES = 100
MASK_KEY = bytes.fromhex("a78840e92f734b36fb")
DICTIONARY_KEYS = (
    "file.appVersionCode", "file.profileFormat", "file.profileName", "file.msg",
    "autorkey", "file.proteger", "bloquearRoot", "onlydata", "onlyPlayStore",
    "blockOperator", "operatorname", "blockHwid", "hwidstring", "loginHwid",
    "blockwifi", "file.validade", "file.pedirLogin", "sshServer", "sshPort",
    "configlineinput", "udplineinput", "proxy_input", "keyPath", "TLS_VERSION",
    "sshUser", "sshPass", "sshPortaLocal", "tunnelType", "dnsForward",
    "dnsResolver1", "dnsResolver2", "udpserver", "udpauth", "udpobfs", "udpport",
    "udpversion", "udpdown", "udpup", "udpbuffer", "v2rayjson", "bhttpUploadSlots",
    "bhttpDownloadSlots", "bhttpBatch", "udpForward", "udpResolver", "wakelock",
    "proxyRemoto", "proxyRemotoPorta", "usarProxyAutenticacao", "protegerConfig",
    "protegerPayload", "protegerSni", "protegerServer", "protegerPort",
    "protegerUser", "protegerPass", "protegerProxy", "psiserverentry", "psiproxy",
    "psiregion", "psitimeout", "psiauth", "currentpsiprotocol", "currentpsiregion",
    "usarDefaultPayload", "optimizedMode", "proxyPayload", "chaveKey",
    "serverNameKey", "dnsKey", "dnsversion", "customSNI",
)
LINK_DICTIONARY = (
    '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n'
    '<!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd">\n'
    '<properties>\n<comment>Archivo de Configuracion</comment>\n'
    + "".join(f'<entry key="{key}"></entry>\n' for key in DICTIONARY_KEYS)
    + "</properties>\n"
).encode("utf-8")


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _base64(text: str, *, urlsafe: bool = False) -> bytes:
    text = re.sub(r"[ \t\r\n]", "", text)
    alphabet = r"[A-Za-z0-9_-]+={0,2}" if urlsafe else r"[A-Za-z0-9+/]+={0,2}"
    if not re.fullmatch(alphabet, text) or len(text) % 4 == 1:
        raise DecodeError("FORMAT_ERROR", "Invalid Base64 profile.")
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4),
                                altchars=b"-_" if urlsafe else None, validate=True)
    except (ValueError, binascii.Error):
        raise DecodeError("FORMAT_ERROR", "Invalid Base64 profile.") from None


def unmask(data: bytes) -> bytes:
    """Inverse of libx.so's byte transform (0x63ee0, decrypt flag 1)."""
    state = 0x91AC3F12
    for value in MASK_KEY:
        state ^= value
    out = bytearray(len(data))
    for index, value in enumerate(data):
        state ^= (state << 13) & 0xFFFFFFFF
        state ^= state >> 17
        state ^= (state << 5) & 0xFFFFFFFF
        key = MASK_KEY[(index + (state & 255)) % len(MASK_KEY)]
        swapped = ((value >> 4) | (value << 4)) & 255
        out[index] = ((swapped - state) & 255) ^ key
    return bytes(out)


def _decrypt_password(data: bytes, password: str | None) -> bytes:
    if not data.startswith(b"UAP1"):
        return data
    if len(data) < 48:
        raise DecodeError("TRUNCATED", "Incomplete UAP1 header or GCM tag.")
    if password is None or password == "":
        raise DecodeError("PASSWORD_REQUIRED", "This profile requires its original export password.")
    try:
        encoded = password.encode("utf-8")
        if len(encoded) > 16384:
            raise DecodeError("SIZE_LIMIT", "Password exceeds 16 KiB of UTF-8.")
    except (AttributeError, UnicodeError):
        raise DecodeError("FORMAT_ERROR", "Password must be valid Unicode text.") from None
    key = hashlib.pbkdf2_hmac("sha256", encoded, data[4:20], 210000, 32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=data[20:32])
    cipher.update(data[:32])
    try:
        return cipher.decrypt_and_verify(data[32:-16], data[-16:])
    except ValueError:
        raise DecodeError("AUTH_FAILED", "Wrong password or damaged UAP1 profile.") from None


def _payload(data: bytes) -> tuple[bytes, str]:
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "Profile exceeds 16 MiB.")
    if data[:4] in (b"EXA1", b"UAB1"):
        inflater = zlib.decompressobj(-15, zdict=LINK_DICTIONARY)
        try:
            xml = inflater.decompress(data[4:], MAX_BYTES + 1)
        except zlib.error:
            raise DecodeError("COMPRESSION_ERROR", "Invalid raw DEFLATE profile or dictionary.") from None
        if len(xml) > MAX_BYTES or inflater.unconsumed_tail:
            raise DecodeError("SIZE_LIMIT", "Decompressed profile exceeds 16 MiB.")
        if not inflater.eof or inflater.unused_data:
            raise DecodeError("COMPRESSION_ERROR", "Truncated DEFLATE profile or trailing data.")
        return xml, data[:4].decode("ascii")
    if data.lstrip().startswith((b"<?xml", b"<properties")):
        return data, "XML"
    raise DecodeError("FORMAT_ERROR", "Expected XML, EXA1 or UAB1 after decoding.")


def _normalize_java_surrogate_references(text: str) -> str:
    """Combine Java XML exports' adjacent UTF-16 surrogate character references.

    Python's XML 1.0 parser correctly rejects individual surrogate references.
    Some Java Properties exporters emit supplementary characters as two numeric
    references (UTF-16 code units), which must be combined into one scalar
    reference. All lone/reordered surrogate references remain invalid.
    """
    matches = iter(re.finditer(r"&#(?:[0-9]+|[xX][0-9A-Fa-f]+);", text))
    current = next(matches, None)
    chunks: list[str] = []
    last = 0

    def codepoint(match: re.Match[str]) -> int:
        token = match.group()
        if len(token) > 20:
            raise DecodeError("INVALID_XML", "Invalid numeric XML reference.")
        return int(token[3:-1], 16) if token[2] in "xX" else int(token[2:-1])

    while current is not None:
        value = codepoint(current)
        if 0xD800 <= value <= 0xDBFF:
            following = next(matches, None)
            if following is None or following.start() != current.end():
                raise DecodeError("INVALID_XML", "Unpaired Java UTF-16 surrogate reference.")
            low = codepoint(following)
            if not 0xDC00 <= low <= 0xDFFF:
                raise DecodeError("INVALID_XML", "Invalid Java UTF-16 surrogate pair.")
            scalar = 0x10000 + ((value - 0xD800) << 10) + (low - 0xDC00)
            chunks.extend((text[last:current.start()], f"&#{scalar};"))
            last = following.end()
            current = next(matches, None)
            continue
        if 0xDC00 <= value <= 0xDFFF:
            raise DecodeError("INVALID_XML", "Unpaired Java UTF-16 surrogate reference.")
        current = next(matches, None)
    chunks.append(text[last:])
    return "".join(chunks)


def _properties(data: bytes, budget: list[int]) -> tuple[dict[str, str], list[str]]:
    budget[0] -= len(data)
    if len(data) > MAX_BYTES or budget[0] < 0:
        raise DecodeError("SIZE_LIMIT", "Decoded XML exceeds its per-profile or aggregate limit.")
    try:
        text = data.decode("utf-8")
        # The standard Java Properties DTD is a format identifier. Never fetch it
        # or expand entity declarations supplied by the input.
        if re.search(r"<!\s*ENTITY", text, re.I):
            raise ValueError
        text = re.sub(r'<!DOCTYPE\s+properties\s+SYSTEM\s+[\'"]http://java\.sun\.com/dtd/properties\.dtd[\'"]\s*>', "", text)
        if re.search(r"<!\s*DOCTYPE", text, re.I):
            raise ValueError
        # Properties.storeToXML emits literal CR in payload values. Avoid
        # ElementTree's XML newline normalization losing the exported CRLF.
        text = re.sub(r'^\s*<\?xml\s+[^?]*\?>', "", text).strip()
        root = ET.fromstring(_normalize_java_surrogate_references(text.replace("\r", "&#13;")))
        if root.tag != "properties" or root.attrib or (root.text or "").strip():
            raise ValueError
        properties: dict[str, str] = {}
        comments: list[str] = []
        for child in root:
            if len(child) or (child.tail or "").strip():
                raise ValueError
            if child.tag == "comment" and not child.attrib:
                comments.append(child.text or "")
            elif child.tag == "entry" and set(child.attrib) == {"key"}:
                key = child.attrib["key"]
                if key in properties or len(properties) >= 100000:
                    raise ValueError
                properties[key] = child.text or ""
            else:
                raise ValueError
        return properties, comments
    except (ValueError, UnicodeError, ET.ParseError, RecursionError):
        raise DecodeError("INVALID_XML", "Expected UTF-8 Java Properties XML without duplicate keys or custom entities.") from None


def _embedded_json(value: str) -> Any:
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError
            result[key] = item
        return result

    def invalid(value):
        raise ValueError

    try:
        obj = json.loads(value, object_pairs_hook=unique, parse_constant=invalid)
        if not isinstance(obj, (dict, list)):
            return None
        stack, count = [(obj, 0)], 0
        while stack:
            node, depth = stack.pop()
            count += 1
            if depth > 64 or count + len(stack) > 100000:
                return None
            if isinstance(node, dict):
                stack.extend((key, depth + 1) for key in node)
                stack.extend((item, depth + 1) for item in node.values())
            elif isinstance(node, list):
                stack.extend((item, depth + 1) for item in node)
            elif isinstance(node, float) and not math.isfinite(node):
                return None
            elif isinstance(node, str):
                node.encode("utf-8")
        return obj
    except (ValueError, RecursionError, UnicodeError):
        return None


def _decode_xml(xml: bytes, password: str | None, budget: list[int], *,
                allow_bundle: bool = True, allow_wrapper: bool = False) -> dict[str, Any]:
    properties, comments = _properties(xml, budget)
    if "file.profilePasswordFormat" in properties:
        expected = {"file.profilePasswordFormat", "file.profileName", "file.passwordPayload"}
        if (not allow_wrapper or set(properties) != expected
                or properties["file.profilePasswordFormat"] != "1"):
            raise DecodeError("FORMAT_ERROR", "Invalid or nested password wrapper.")
        blob = _base64(properties["file.passwordPayload"])
        if not blob.startswith(b"UAP1"):
            raise DecodeError("FORMAT_ERROR", "Password wrapper must contain UAP1.")
        inner, _ = _payload(_decrypt_password(blob, password))
        profile = _decode_xml(inner, password, budget, allow_bundle=False)
        if profile["properties"].get("file.proteger") != "1":
            raise DecodeError("FORMAT_ERROR", "Protected bundle member must have file.proteger=1.")
        profile["passwordEnvelope"] = {"properties": properties, "comments": comments}
        return profile
    result: dict[str, Any] = {"type": "profile", "properties": properties, "comments": comments}
    if "file.bundleFormat" in properties:
        if not allow_bundle or properties["file.bundleFormat"] != "UA-BUNDLE-1":
            raise DecodeError("UNSUPPORTED_BUNDLE", "Unsupported or nested bundle format.")
        count_text = properties.get("file.profileCount", "")
        if not re.fullmatch(r"[0-9]{1,3}", count_text):
            raise DecodeError("FORMAT_ERROR", "Invalid bundle profile count.")
        count = int(count_text)
        expected = {"file.bundleFormat", "file.profileCount"} | {f"profile.{i}" for i in range(count)}
        if not 1 <= count <= MAX_PROFILES or set(properties) != expected:
            raise DecodeError("FORMAT_ERROR", "Bundle must contain exactly 1 to 100 indexed profiles.")
        result["type"] = "bundle"
        result["profiles"] = []
        for i in range(count):
            raw = properties[f"profile.{i}"]
            if not raw.strip():
                raise DecodeError("FORMAT_ERROR", "Bundle contains an empty profile.")
            result["profiles"].append(_decode_xml(raw.encode("utf-8"), password, budget,
                                                    allow_bundle=False, allow_wrapper=True))
    elif "v2rayjson" in properties:
        parsed = _embedded_json(properties["v2rayjson"])
        if parsed is not None:
            result["embeddedJson"] = {"v2rayjson": parsed}
    return result


def decode(data: bytes | str, *, password: str | None = None) -> dict[str, Any]:
    """Decode a .ua file or ua:// text; return all properties and all members.

    Failure in any bundle member aborts the whole result. Import-policy flags
    remain visible but are not executed. Unpassworded files are not authenticated.
    """
    if not isinstance(data, (bytes, str)):
        raise DecodeError("FORMAT_ERROR", "Expected .ua bytes or ua:// text.")
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "Input exceeds 16 MiB.")
    try:
        text = data.decode("utf-8-sig") if isinstance(data, bytes) else data.removeprefix("\ufeff")
        if len(text.encode("utf-8")) > MAX_BYTES:
            raise DecodeError("SIZE_LIMIT", "Input exceeds 16 MiB.")
    except UnicodeError:
        raise DecodeError("FORMAT_ERROR", "Expected UTF-8 Base64URL input.") from None
    text = text.strip()
    if text.startswith("ua://"):
        text = text[5:].strip()
    outer = unmask(_base64(text, urlsafe=True))
    protected = outer.startswith(b"UAP1")
    xml, payload_format = _payload(_decrypt_password(outer, password))
    result = _decode_xml(xml, password, [MAX_TOTAL_XML_BYTES])
    result["encoding"] = {"transport": "ua-base64url", "payload": payload_format,
                          "passwordProtected": protected}
    return result


def run(file_bytes: bytes | str, *, password: str | None = None) -> str | None:
    try:
        return json.dumps(decode(file_bytes, password=password), ensure_ascii=False, indent=2) + "\n"
    except DecodeError:
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decode Ultra Custom 5.2 .ua files, ua:// links and profile bundles offline.")
    parser.add_argument("file", type=Path, help=".ua file or text file containing ua://...")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--ask-password", action="store_true", help="Prompt privately for the original export password")
    group.add_argument("--password-file", type=Path, help="UTF-8 password file; removes one final LF or CRLF")
    parser.add_argument("-o", "--output", type=Path, help="Save complete JSON instead of printing it")
    args = parser.parse_args(argv)
    try:
        password = None
        if args.password_file is not None:
            with args.password_file.open("rb") as handle:
                raw_password = handle.read(16387)
            if raw_password.endswith(b"\r\n"):
                raw_password = raw_password[:-2]
            elif raw_password.endswith(b"\n"):
                raw_password = raw_password[:-1]
            if len(raw_password) > 16384:
                raise DecodeError("SIZE_LIMIT", "Password exceeds 16 KiB of UTF-8.")
            try:
                password = raw_password.decode("utf-8")
            except UnicodeError:
                raise DecodeError("FORMAT_ERROR", "Password file must use UTF-8.") from None
        elif args.ask_password:
            password = getpass.getpass("Export password: ")
        with args.file.open("rb") as handle:
            raw = handle.read(MAX_BYTES + 1)
        result = json.dumps(decode(raw, password=password), ensure_ascii=False, indent=2) + "\n"
        if args.output is not None:
            args.output.write_text(result, encoding="utf-8")
        else:
            sys.stdout.write(result)
        return 0
    except DecodeError as error:
        print(json.dumps({"error": error.code, "message": str(error)}), file=sys.stderr)
        return 1
    except (OSError, EOFError):
        print(json.dumps({"error": "IO_ERROR", "message": "Cannot read input/password or write output."}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
