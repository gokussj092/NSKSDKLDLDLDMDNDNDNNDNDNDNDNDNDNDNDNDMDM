# Dossier copy (CAT 103): SANITIZED. Format key material is NOT stored
# in this file; supply it via the environment variables documented
# below and in REPRODUCE.md. Never commit keys, tokens or passwords here.
"""Peru VPN 4.1.2 catalog: StringCrypter envelope and NoobCrypt fields.

Peru VPN (package com.peru.vpn, versionCode 412) is a TunnelDOOM rebrand:
its code lives under com.tunneldoom.http / com.tunneldoom.sshservice and its
crypto is identical to TunnelDOOM 4.3.5, verified in Peru VPN's own
decompiled source (ConfigUpdateco.java, crypt/StringCrypter.java,
crypt/NoobPass.java, crypt/NoobCrypt.java):

- Catalog source: GET https://free.tunneldoom.space/config.json, plain GET,
  no headers of its own, no auth, no token. The dead host
  web.tunneldoom.space does NOT appear anywhere in Peru VPN 4.1.2's DEX
  (0 occurrences); the fixed host free.tunneldoom.space is the literal in
  ConfigUpdateco.doInBackground. Peru VPN 4.1.2 already uses the fixed host.
- Envelope: StringCrypter XOR envelope (SHA-256 of a fixed label),
  32-char hex salt prefix. The label is a format constant from the
  APK; the derived 32-byte key is supplied via PERU_CATALOG_KEY_HEX.
- Fields: NoobCrypt AES-256-CBC, IV of 16 zero bytes, PKCS7; key is SHA-256
  of a fixed obfuscated string from the APK, XORed with a 4-char mask and
  reversed. The derived 32-byte key is supplied via PERU_FIELD_KEY_HEX.

Verified live 2026-11-28: catalog Version 532, 390 servers, every field
decrypts with these unchanged keys. The bundled res/raw/noobdev.txt also
decrypts with this codec (Version 2, 8 Peru template servers).

Offline only. Fixed build parameters are not account/device credentials.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

MAX_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 200_000
# Dossier copy (CAT 103): the envelope key and the field key are fixed
# format constants from the APK. They are NOT stored in this file;
# supply the derived 32-byte keys as hex via the environment:
#   PERU_CATALOG_KEY_HEX = SHA-256 of the StringCrypter label (64 hex)
#   PERU_FIELD_KEY_HEX   = SHA-256 of the de-obfuscated NoobPass string (64 hex)
# (derivation documented in ANALYSIS.md; values only in the batch report).
_TEST_KEYS = os.environ.get("PERU_TEST_KEYS") == "1"
TEST_CATALOG_KEY = bytes.fromhex("11" * 32)
TEST_FIELD_KEY = bytes.fromhex("22" * 32)


def _load_hex_key(env_name):
    raw = os.environ.get(env_name, "")
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        key = b""
    if len(key) != 32:
        raise DecodeError("KEYS_NOT_CONFIGURED")
    return key


def _catalog_key():
    if _TEST_KEYS:
        return TEST_CATALOG_KEY
    return _load_hex_key("PERU_CATALOG_KEY_HEX")


def _field_key():
    if _TEST_KEYS:
        return TEST_FIELD_KEY
    return _load_hex_key("PERU_FIELD_KEY_HEX")
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
    text = bytes(b ^ _catalog_key()[i % 32] for i, b in enumerate(raw)).decode("utf-8")
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
    return unpad(AES.new(_field_key(), AES.MODE_CBC, iv=bytes(16)).decrypt(raw), 16).decode("utf-8")


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
    except DecodeError:
        raise
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        raise DecodeError("INVALID_PERU_VPN_CATALOG") from exc


def render(value: dict) -> str:
    result = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)
    if len(result.encode("utf-8")) > MAX_BYTES:
        raise DecodeError("OUTPUT_TOO_LARGE")
    return result


def run(data: bytes) -> str:
    return render(decode_catalog(data))
