"""HTTP Jireh 2.0: APK-derived nibble/AES-CBC catalog and ROT22 fields."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Reuse the byte-identical SKS importer and validation primitives, without
# duplicating a historical engine. This sibling is shipped in the download ZIP.
if __package__ and '.' in __package__:
    from ..HTTP_FenixVPN import codec as shared
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from HTTP_FenixVPN import codec as shared

DecodeError = shared.DecodeError
MAX_BYTES = shared.MAX_BYTES
MAX_FILE_BYTES = shared.MAX_FILE_BYTES
render = shared.render
ALPHABET = '@#$_&-+()/*"!:;?'
CATALOG_PASSWORD = b"Conexcol@45208!"
CATALOG_KEY = hashlib.sha256(CATALOG_PASSWORD.hex().upper().encode("ascii")).digest()
FIELD_KEY = b"conexcolvpn@2308"
SERVER_FIELDS = frozenset(("ServerIP", "ProxyIP", "ServerUser", "ServerPass", "Payload", "SNI",
    "Slowchave", "Nameserver", "Slowdns", "V2rayConfig", "UdpServer", "UdpObfs", "UdpAuth",
    "UdpDown", "UdpUp", "UdpBuffer"))
USER_FIELDS = frozenset(("Username", "Password", "Obfs", "Auth", "ID", "Path"))


def decrypt_catalog(data: bytes, *, key: bytes = CATALOG_KEY) -> str:
    text = shared._bounded(data).decode("utf-8-sig").strip()
    if not text or len(text) % 2 or any(c not in ALPHABET for c in text):
        raise DecodeError("Alfabeto de catálogo inválido.")
    raw = bytes(ALPHABET.index(text[i]) * 16 + ALPHABET.index(text[i+1]) for i in range(0, len(text), 2))
    ciphertext = shared._base64(raw.decode("ascii"))
    if not ciphertext or len(ciphertext) % 16:
        raise DecodeError("Sobre de catálogo inválido.")
    return unpad(AES.new(key, AES.MODE_CBC, bytes(16)).decrypt(ciphertext), 16).decode("utf-8")


def decode_field(value: str, *, key: bytes = FIELD_KEY, rotation: int = 22) -> str:
    if value == "":
        return value
    raw = shared._base64(value)
    if not raw or len(raw) % 16:
        raise DecodeError("Campo AES-CBC inválido.")
    text = unpad(AES.new(key, AES.MODE_CBC, bytes(16)).decrypt(raw), 16).decode("utf-8")
    # JirehActivity.o00Oo0(str, 4) calls o00O0O(str, 26-4).
    return shared.rotate_java(text, rotation)


def decode_catalog(data: bytes, *, catalog_key: bytes = CATALOG_KEY,
                   field_key: bytes = FIELD_KEY, rotation: int = 22) -> dict:
    try:
        obj = json.loads(decrypt_catalog(data, key=catalog_key), object_pairs_hook=shared._unique, parse_constant=shared._constant)
        shared._validate(obj)
        if not isinstance(obj, dict) or not isinstance(obj.get("Version"), str) or not obj["Version"]:
            raise DecodeError("Estructura de catálogo incompatible.")
        names = [name for name in ("Servers", "Usuarios") if name in obj]
        if not names:
            raise DecodeError("El catálogo no contiene perfiles.")
        result = obj.copy()
        for name in names:
            items = obj[name]
            if not isinstance(items, list) or not items or any(not isinstance(x, dict) or not x for x in items):
                raise DecodeError("Lista de perfiles inválida.")
            fields = SERVER_FIELDS if name == "Servers" else USER_FIELDS
            decoded = []
            for item in items:
                if not isinstance(item.get("Name"), str):
                    raise DecodeError("El perfil no contiene su nombre.")
                entry = item.copy()
                for key in fields & item.keys():
                    if not isinstance(item[key], str):
                        raise DecodeError("Un campo cifrado no contiene texto.")
                    entry[key] = decode_field(item[key], key=field_key, rotation=rotation)
                decoded.append(entry)
            result[name] = decoded
        shared._validate(result)
        return result
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise DecodeError("Catálogo inválido o no compatible con HTTP Jireh 2.0.") from exc


def decode_profile(data: bytes) -> dict:
    try:
        return shared.decode_profile(data)
    except DecodeError as exc:
        raise DecodeError("Archivo inválido o no compatible con HTTP Jireh 2.0.") from exc
