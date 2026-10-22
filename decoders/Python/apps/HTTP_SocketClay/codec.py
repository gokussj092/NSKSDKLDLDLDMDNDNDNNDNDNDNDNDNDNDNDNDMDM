"""HTTP SocketClay 3.4.0: offline WakkoDev/ChaCha/AES/versioned-field reader."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Util.Padding import unpad

# Byte-identical .sks import/export primitives; retain the existing shared route.
if __package__ and "." in __package__:
    from ..HTTP_FenixVPN import codec as shared
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from HTTP_FenixVPN import codec as shared

DecodeError = shared.DecodeError
MAX_BYTES = shared.MAX_BYTES
MAX_FILE_BYTES = shared.MAX_FILE_BYTES
render = shared.render
# Build constants, never credentials obtained from a downloaded catalog.
CATALOG_PASSWORD = '⚡💕NAJU❤️221223💕⚡'.encode("utf-8")
CHACHA_KEY = bytes.fromhex("93275eb144c8196aef027d35a9581cd46fb7218a3ec59014da734be20f619d28")
VERSION_SECRET = 'NJ22pX9mQaWK7Rt4Vz8HyLcDuK'
ROTATION = 19  # Configs.INPUT=7; decode rotates Java letters by 26-7.
_names = json.loads(Path(__file__).with_name("field_names.json").read_text("utf-8"))
SERVER_FIELDS = frozenset(_names["servers"].values())
USER_FIELDS = frozenset(_names["users"].values())


def field_key(version: str) -> bytes:
    if not isinstance(version, str) or not version or len(version) > 128:
        raise DecodeError("Versión de catálogo inválida.")
    digest = hashlib.sha256((VERSION_SECRET + version).encode("utf-8")).digest()
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(alphabet[b % 62] for b in digest[:16]).encode("ascii").ljust(32, b"\0")


def decrypt_catalog(data: bytes) -> str:
    raw = shared._base64(shared._bounded(data).decode("utf-8-sig").strip())
    if len(raw) < 32 or raw[:8] != b"WakkoDev" or (len(raw) - 16) % 16:
        raise DecodeError("Sobre WakkoDev inválido.")
    material = previous = b""
    while len(material) < 48:
        previous = hashlib.md5(previous + CATALOG_PASSWORD + raw[8:16]).digest()
        material += previous
    return unpad(AES.new(material[:32], AES.MODE_CBC, material[32:48]).decrypt(raw[16:]), 16).decode("utf-8")


def decode_field(value: str, key: bytes) -> str:
    if not isinstance(value, str):
        raise DecodeError("El campo cifrado no contiene texto.")
    if value == "":
        return value
    raw = shared._base64(value, urlsafe=True)
    # AESED direct values are IV16 + n*16 ciphertext. Wrapped values have
    # nonce12 + unpadded URL-Base64(AESED) + tag16, whose length is never 0 mod16.
    # Select before decrypting; a failed ChaCha tag must never fall back to CBC.
    if len(raw) % 16:
        if len(raw) < 28:
            raise DecodeError("Sobre ChaCha20-Poly1305 inválido.")
        cipher = ChaCha20_Poly1305.new(key=CHACHA_KEY, nonce=raw[:12])
        inner = cipher.decrypt_and_verify(raw[12:-16], raw[-16:]).decode("utf-8").strip()
        raw = shared._base64(inner, urlsafe=True)
    if len(raw) < 32 or len(raw) % 16:
        raise DecodeError("Campo AES-CBC inválido.")
    plain = unpad(AES.new(key, AES.MODE_CBC, raw[:16]).decrypt(raw[16:]), 16).decode("utf-8")
    return shared.rotate_java(plain, ROTATION)


def decode_catalog_fields(data: bytes, *, server_fields: frozenset, user_fields: frozenset, display_key: str) -> dict:
    """Shared verified wire recipe; callers provide their APK-specific field schema."""
    obj = json.loads(decrypt_catalog(data), object_pairs_hook=shared._unique, parse_constant=shared._constant)
    shared._validate(obj)
    if not isinstance(obj, dict):
        raise DecodeError("Estructura de catálogo incompatible.")
    key = field_key(obj.get("Version"))
    lists = [name for name in ("Servers", "Usuarios") if name in obj]
    if not lists:
        raise DecodeError("El catálogo no contiene perfiles.")
    result = obj.copy()
    for name in lists:
        items = obj[name]
        if not isinstance(items, list) or not items or any(not isinstance(item, dict) or not item for item in items):
            raise DecodeError("Lista de perfiles inválida.")
        fields = server_fields if name == "Servers" else user_fields
        name_key = display_key if name == "Servers" else "Name"
        decoded = []
        for item in items:
            if not isinstance(item.get(name_key), str):
                raise DecodeError("El perfil no contiene su nombre.")
            entry = item.copy()
            for field in fields & item.keys():
                entry[field] = decode_field(item[field], key)
            decoded.append(entry)
        result[name] = decoded
    shared._validate(result)
    return result


def decode_catalog(data: bytes) -> dict:
    try:
        return decode_catalog_fields(data, server_fields=SERVER_FIELDS, user_fields=USER_FIELDS, display_key=_names["servers"]["sName"])
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise DecodeError("Catálogo inválido o no compatible con HTTP SocketClay 3.4.0.") from exc


def decode_profile(data: bytes) -> dict:
    try:
        return shared.decode_profile(data)
    except DecodeError as exc:
        raise DecodeError("Archivo inválido o no compatible con HTTP SocketClay 3.4.0.") from exc
