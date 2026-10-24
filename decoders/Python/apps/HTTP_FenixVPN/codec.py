"""HTTP FenixVPN 19.4: independently recovered SKS and WakkoDev recipes."""
from __future__ import annotations

import base64
import hashlib
import json
import math
from pathlib import Path
import unicodedata
from xml.etree import ElementTree as ET

from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import unpad

MAX_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_DEPTH = 64
CATALOG_PASSWORD = "\U0001f525\U0001f525\U0001f525vpnfenix\u2b50\ufe0f\u2b50\ufe0f\u2b50\ufe0f".encode()
FIELD_KEY = b"FenxM22_07!89Dev".ljust(32, b"\0")
PROFILE_PASSWORD = b"fubvx788b46v"
LEGACY_DES_KEY = b"cinbdf66"  # DESKeySpec uses the first eight password bytes.
_names = json.loads(Path(__file__).with_name("field_names.json").read_text("utf-8"))
SERVER_FIELDS = frozenset(_names["servers"])
USER_FIELDS = frozenset(_names["users"])


class DecodeError(ValueError):
    """No input or decrypted credentials in error messages."""


def _bounded(data: bytes, limit=MAX_BYTES) -> bytes:
    if not isinstance(data, bytes) or not data or len(data) > limit:
        raise DecodeError("Entrada vacía o superior al límite permitido.")
    return data


def _base64(value: str, *, urlsafe=False) -> bytes:
    clean = "".join(value.split()).encode("ascii")
    if not clean or len(clean) % 4 == 1:
        raise DecodeError("Base64 inválido.")
    if urlsafe:
        clean = clean.translate(bytes.maketrans(b"-_", b"+/"))
    return base64.b64decode(clean + b"=" * (-len(clean) % 4), validate=True)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DecodeError("JSON con claves duplicadas.")
        result[key] = value
    return result


def _constant(_value):
    raise DecodeError("JSON con números no finitos.")


def _validate(value, depth=0):
    if depth > MAX_DEPTH:
        raise DecodeError("Profundidad superior a 64.")
    if isinstance(value, dict):
        for key, item in value.items():
            key.encode("utf-8")
            _validate(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _validate(item, depth + 1)
    elif isinstance(value, str):
        value.encode("utf-8")
    elif isinstance(value, float) and not math.isfinite(value):
        raise DecodeError("Número fuera del rango JSON.")


def decrypt_catalog(data: bytes) -> str:
    raw = _base64(_bounded(data).decode("utf-8-sig").strip())
    if len(raw) < 32 or raw[:8] != b"WakkoDev" or (len(raw) - 16) % 16:
        raise DecodeError("Sobre WakkoDev inválido.")
    # Exact AbstractC6343 MD5 chaining; not OpenSSL Salted__ or PBKDF2.
    material = previous = b""
    while len(material) < 48:
        previous = hashlib.md5(previous + CATALOG_PASSWORD + raw[8:16]).digest()
        material += previous
    return unpad(AES.new(material[:32], AES.MODE_CBC, material[32:48]).decrypt(raw[16:]), 16).decode("utf-8")


def rotate_java(text: str, shift=21) -> str:
    """C6334: Java Character predicates on UTF-16 chars, not ASCII ROT alone."""
    raw = text.encode("utf-16-le")
    out = bytearray()
    for i in range(0, len(raw), 2):
        code = int.from_bytes(raw[i:i + 2], "little")
        char = chr(code)
        if unicodedata.category(char).startswith("L"):
            start = 65 if char.isupper() else 97
            code = (code + shift - start) % 26 + start
        out.extend(code.to_bytes(2, "little"))
    return out.decode("utf-16-le")


def decode_field(value: str) -> str:
    # Empty optional fields carry no ciphertext. Preserve them, do not emit
    # AbstractC6344's UI error sentinel ("ERROR", then shifted by the caller).
    if value == "":
        return value
    raw = _base64(value, urlsafe=True)
    if len(raw) < 32 or len(raw) % 16:
        raise DecodeError("Campo AES-CBC inválido.")
    text = unpad(AES.new(FIELD_KEY, AES.MODE_CBC, raw[:16]).decrypt(raw[16:]), 16).decode("utf-8")
    return rotate_java(text)


def decode_catalog(data: bytes) -> dict:
    try:
        obj = json.loads(decrypt_catalog(data), object_pairs_hook=_unique, parse_constant=_constant)
        _validate(obj)
        if not isinstance(obj, dict) or not isinstance(obj.get("Version"), str) or not obj["Version"]:
            raise DecodeError("Estructura de catálogo incompatible.")
        lists = [name for name in ("Servers", "Usuarios") if name in obj]
        if not lists:
            raise DecodeError("El catálogo no contiene perfiles.")
        result = obj.copy()
        for name in lists:
            items = obj[name]
            if not isinstance(items, list) or not items or any(not isinstance(item, dict) or not item for item in items):
                raise DecodeError("Lista de perfiles inválida.")
            fields = SERVER_FIELDS if name == "Servers" else USER_FIELDS
            decoded = []
            for item in items:
                display_key = "p0PgL3l0d89mnssz7ImPJA==" if name == "Servers" else "Name"
                if not isinstance(item.get(display_key), str):
                    raise DecodeError("El perfil no contiene su nombre.")
                entry = item.copy()
                for key in fields & item.keys():
                    if not isinstance(item[key], str):
                        raise DecodeError("Un campo cifrado no contiene texto.")
                    entry[key] = decode_field(item[key])
                decoded.append(entry)
            result[name] = decoded
        _validate(result)
        return result
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise DecodeError("Catálogo inválido o no compatible con HTTP FenixVPN 19.4.") from exc


def decrypt_profile(data: bytes) -> str:
    data = _bounded(data, MAX_FILE_BYTES)
    # Select by wire format before decrypting. A failed GCM tag never falls
    # back to DES. The historical importer has both independently verified keys.
    if data.count(b".") == 2 and data.isascii():
        salt, nonce, sealed = (_base64(part) for part in data.decode("ascii").strip().split("."))
        if len(salt) != 32 or len(nonce) != 12 or len(sealed) <= 16:
            raise DecodeError("Sobre AES-GCM inválido.")
        key = hashlib.pbkdf2_hmac("sha256", PROFILE_PASSWORD, salt, 1000, 16)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
        return cipher.decrypt_and_verify(sealed[:-16], sealed[-16:]).decode("utf-8")
    if len(data) % 8:
        raise DecodeError("Archivo SKS incompatible.")
    return unpad(DES.new(LEGACY_DES_KEY, DES.MODE_ECB).decrypt(data), 8).decode("utf-8")


def decode_profile(data: bytes) -> dict:
    try:
        text = decrypt_profile(data)
        # Java Properties XML uses this external DTD. ElementTree does not
        # fetch it; reject declared entities before parsing untrusted XML.
        if "<!ENTITY" in text.upper():
            raise DecodeError("Declaraciones de entidades no permitidas.")
        root = ET.fromstring(text)
        if root.tag != "properties":
            raise DecodeError("Se esperaba XML Java Properties.")
        pending = [(root, 0)]
        while pending:
            node, depth = pending.pop()
            if depth > MAX_DEPTH:
                raise DecodeError("Profundidad XML superior a 64.")
            pending.extend((child, depth + 1) for child in node)
        entries = []
        for child in root:
            if child.tag == "entry":
                if set(child.attrib) != {"key"} or len(child):
                    raise DecodeError("Entrada Java Properties inválida.")
                entries.append({"key": child.attrib["key"], "value": child.text or ""})
            elif child.tag != "comment":
                raise DecodeError("XML Java Properties incompatible.")
        if not entries:
            raise DecodeError("El perfil no contiene entradas.")
        # Keep every entry, duplicate key, empty/multiline value and the exact
        # source XML. Do not rename opaque keys or coerce string flags to booleans.
        value = {"entries": entries, "raw_xml": text}
        _validate(value)
        return value
    except (ValueError, UnicodeError, RecursionError, ET.ParseError) as exc:
        raise DecodeError("Archivo inválido o no compatible con HTTP FenixVPN 19.4.") from exc


def render(value) -> str:
    result = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)
    if len(result.encode("utf-8")) > MAX_BYTES:
        raise DecodeError("La salida supera 8 MiB.")
    return result
