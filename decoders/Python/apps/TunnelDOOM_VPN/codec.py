"""TunnelDOOM 4.2.4 catalog: StringCrypter envelope and NoobCrypt fields.

Offline only. Fixed build parameters are not account/device credentials.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

MAX_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 200_000
CATALOG_KEY = hashlib.sha256(b"test_key").digest()
# NoobPass.star -> XOR Java chars with QXWR -> StringBuilder.reverse.
_STAR = "up1!\x05 ,/\x0fq&)k6ts{1305*+$"
FIELD_KEY = hashlib.sha256("".join(
    chr(ord(c) ^ ord("QXWR"[i % 4])) for i, c in enumerate(_STAR)
)[::-1].encode("utf-8")).digest()
# SocketClayMainActivity.j1 -> Y0 -> w1 -> Utils.decrypt. Other fields
# (including ports, Name, FLAG and booleans) are already cleartext.
SERVER_FIELDS = frozenset((
    "ServerUser", "ServerPass", "ServerIP", "ProxyIP", "Payload", "SNI",
    "Slowchave", "Nameserver", "Slowdns", "UdpBuffer", "UdpDown", "UdpUp",
    "V2rayConfig",
))


class DecodeError(ValueError):
    """Sanitized failure: never include ciphertext or connection parameters."""


def _base64(text: str) -> bytes:
    clean = re.sub(r"[\t\r\n ]", "", text).encode("ascii")
    if not clean or len(clean) % 4 == 1:
        raise DecodeError("INVALID_BASE64")
    return base64.b64decode(clean + b"=" * (-len(clean) % 4), validate=True)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DecodeError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _nonfinite(_value):
    raise DecodeError("INVALID_JSON_NUMBER")


def _validate(root):
    pending = [(root, 0)]
    nodes = 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if depth > MAX_DEPTH or nodes > MAX_NODES:
            raise DecodeError("CATALOG_COMPLEXITY_LIMIT")
        if isinstance(value, dict):
            for key, item in value.items():
                key.encode("utf-8")
                pending.append((item, depth + 1))
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
        elif isinstance(value, str):
            value.encode("utf-8")
        elif isinstance(value, float) and not math.isfinite(value):
            raise DecodeError("INVALID_JSON_NUMBER")


def decrypt_catalog(data: bytes) -> str:
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError("INVALID_INPUT_SIZE")
    raw = _base64(data.decode("utf-8-sig"))
    text = bytes(b ^ CATALOG_KEY[i % 32] for i, b in enumerate(raw)).decode("utf-8")
    # processString('e') prepends 16 salt bytes as 32 ASCII hex characters.
    if not re.match(r"\A[0-9a-fA-F]{32}", text):
        raise DecodeError("INVALID_CATALOG_ENVELOPE")
    return text[32:]


def decode_field(value: str) -> str:
    if value == "":
        return ""
    raw = _base64(value)
    if not raw or len(raw) % 16:
        raise DecodeError("INVALID_FIELD_ENVELOPE")
    return unpad(AES.new(FIELD_KEY, AES.MODE_CBC, iv=b"\0" * 16).decrypt(raw), 16).decode("utf-8")


def decode_catalog(data: bytes) -> dict:
    try:
        obj = json.loads(decrypt_catalog(data), object_pairs_hook=_unique, parse_constant=_nonfinite)
        _validate(obj)
        if (not isinstance(obj, dict) or not isinstance(obj.get("Version"), str)
                or not obj["Version"] or not isinstance(obj.get("Servers"), list)
                or not obj["Servers"]):
            raise DecodeError("INVALID_CATALOG_SCHEMA")
        for entry in obj["Servers"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("Name"), str):
                raise DecodeError("INVALID_SERVER_SCHEMA")
            for name in SERVER_FIELDS & entry.keys():
                if not isinstance(entry[name], str):
                    raise DecodeError("INVALID_FIELD_TYPE")
                entry[name] = decode_field(entry[name])
        _validate(obj)
        return obj
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        raise DecodeError("INVALID_TUNNELDOOM_CATALOG") from exc


def render(value: dict) -> str:
    result = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)
    if len(result.encode("utf-8")) > MAX_BYTES:
        raise DecodeError("OUTPUT_TOO_LARGE")
    return result


def run(data: bytes) -> str:
    return render(decode_catalog(data))
