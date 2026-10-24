"""MM Tunnel v1.10.11.1 (45): source-confirmed Argon2id/AES-GCM envelopes.

No Android/SO, user password, network, clock or device identity is needed.
Only authentic inner fields are returned; malformed protected fields fail closed.
"""
from __future__ import annotations

import base64
import binascii
import json
import math
import re

from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import AES

MAX_BYTES = 8 * 1024 * 1024
MAX_FIELDS = 8192
FILE_SECRET = b"iOi/hqT/TocUv0UbDImfWPGR1mfSdzzX"
FIELD_SECRET = b"NewDecryptLibPassword"
PROTECTED_FIELDS = frozenset({
    "DefOVPNUser", "DefOVPNPass", "HysteriaUser", "HysteriaOBFS", "DefaultOVPNCert",
    "ServerIPHost", "OVPNUser", "OVPNPass", "UDP_obfs", "UDP_user", "CustomCertificate",
    "SlowDNSHost", "SlowDNSKey", "V2rayUUID", "H2pass", "TrojanPass", "V2rayPath",
    "Payload", "CustomProxy", "SNI", "V2rayConfig", "BugDNS", "V2rayAddress",
    "V2rayHost", "V2raySNI", "Info", "URI",
})


class DecodeError(ValueError):
    pass


def input_text(data: bytes) -> str:
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError("INVALID_INPUT")
    try:
        text = data.decode("utf-8-sig").strip()
    except UnicodeError as exc:
        raise DecodeError("INVALID_UTF8") from exc
    if not text:
        raise DecodeError("INVALID_INPUT")
    return text


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise DecodeError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _json(text):
    def invalid(_):
        raise DecodeError("INVALID_JSON")
    try:
        obj = json.loads(text, object_pairs_hook=_pairs, parse_constant=invalid)
        # Validate UTF-8, finite numbers and nesting, including escaped surrogates.
        render(obj).encode("utf-8")
        return obj
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("INVALID_JSON") from exc


def render(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, allow_nan=False)


def _base64(text: str) -> bytes:
    # Go StdEncoding ignores CR/LF, but not arbitrary whitespace or URL-safe data.
    text = text.replace("\r", "").replace("\n", "")
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DecodeError("INVALID_BASE64") from exc
    if len(raw) < 44 or len(raw) > MAX_BYTES:
        raise DecodeError("INVALID_ENVELOPE")
    return raw


def open_envelope(text: str, *, exported: bool = False) -> str:
    if not isinstance(text, str) or len(text) > MAX_BYTES:
        raise DecodeError("INVALID_INPUT")
    if exported:
        # Encrypt inserts one random ASCII letter at byte index 3 AFTER Base64.
        if len(text) < 4 or text[3] not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ":
            raise DecodeError("INVALID_EXPORT_MARKER")
        text = text[:3] + text[4:]
    raw = _base64(text)
    salt, nonce = raw[:16], raw[16:28]
    key = hash_secret_raw(FILE_SECRET if exported else FIELD_SECRET, salt,
                          time_cost=3, memory_cost=16384, parallelism=1,
                          hash_len=32, type=Type.ID, version=19)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(salt)
    try:
        return cipher.decrypt_and_verify(raw[28:-16], raw[-16:]).decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("AUTHENTICATION_FAILED") from exc


def decode_fields(obj):
    # Cache is private to this document. No decoded credentials survive a request.
    cache = {}
    nodes = 0

    def walk(value, key="", depth=0):
        nonlocal nodes
        nodes += 1
        if depth > 48 or nodes > 200000:
            raise DecodeError("JSON_LIMIT")
        if isinstance(value, dict):
            return {k: walk(v, k, depth + 1) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v, "", depth + 1) for v in value]
        if isinstance(value, float) and not math.isfinite(value):
            raise DecodeError("INVALID_JSON")
        if isinstance(value, str) and key in PROTECTED_FIELDS:
            # Plaintext is permitted by Hometab.Companion.a. Only shaped Base64
            # envelopes enter the KDF; damaged tags never become partial output.
            normalized = value.replace("\r", "").replace("\n", "")
            if len(normalized) < 60 or not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", normalized):
                return value
            if normalized in cache:
                return cache[normalized]
            if len(cache) >= MAX_FIELDS:
                raise DecodeError("FIELD_LIMIT")
            clear = open_envelope(value)
            cache[normalized] = clear
            return clear
        return value

    return walk(obj)


def decode_file(data: bytes):
    text = input_text(data)
    if text.startswith("{"):
        obj = _json(text)
    else:
        # ConfigFileParser first calls parseConfig (Encrypt) then DO (EO).
        try:
            clear = open_envelope(text, exported=True)
        except DecodeError:
            clear = open_envelope(text)
        obj = _json(clear)
    if (not isinstance(obj, dict) or not isinstance(obj.get("Name"), str)
            or not isinstance(obj.get("TunnelType"), str)):
        raise DecodeError("INVALID_MM_PROFILE")
    return decode_fields(obj)


def decode_catalog(data: bytes):
    text = input_text(data)
    if text.startswith("{"):
        obj = _json(text)
    else:
        # Bundled catalog uses EO/DO; the fixed updater uses Encrypt/decrypt.
        try:
            clear = open_envelope(text, exported=True)
        except DecodeError:
            clear = open_envelope(text)
        obj = _json(clear)
    if (not isinstance(obj, dict) or not isinstance(obj.get("Version"), str)
            or not all(isinstance(obj.get(k), list) for k in ("Servers", "Networks"))
            or not all(isinstance(v, dict) for k in ("Servers", "Networks") for v in obj[k])):
        raise DecodeError("INVALID_MM_CATALOG")
    return decode_fields(obj)
