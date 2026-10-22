"""TunelGuard 12.8: current STGCM2.TG catalog and native .tgv CBC profile."""
from __future__ import annotations
import json
from pathlib import Path
import re
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
if __package__ and "." in __package__:
    from ..HTTP_FenixVPN import codec as shared
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from HTTP_FenixVPN import codec as shared

DecodeError = shared.DecodeError
MAX_BYTES = shared.MAX_BYTES
MAX_FILE_BYTES = shared.MAX_FILE_BYTES
render = shared.render
PREFIX = b"STGCM2.TG."
# Parameters recovered from build 128 libfrkudp.so, not downloaded credentials.
CATALOG_KEY = bytes.fromhex("c09300e6f86c0e11c9bf709289481023d57655095bf2b7452204bb2e3d623ede")
FILE_KEY = bytes.fromhex("5447565f555345525f43304e4631475f")
NAMES = json.loads(Path(__file__).with_name("field_names.json").read_text("utf-8"))


def xor_java(text: str) -> str:
    if not isinstance(text, str):
        raise DecodeError("El campo codificado no contiene texto.")
    raw = text.encode("utf-16-le", "surrogatepass")
    out = bytearray()
    masks = (30482, 14551, 22566, 65535)
    for i in range(0, len(raw), 2):
        value = int.from_bytes(raw[i:i+2], "little") ^ masks[(i//2) % 4]
        out.extend(value.to_bytes(2, "little"))
    return out.decode("utf-16-le")


def _json(text: str) -> dict:
    obj = json.loads(text, object_pairs_hook=shared._unique, parse_constant=shared._constant)
    shared._validate(obj)
    if not isinstance(obj, dict) or not obj:
        raise DecodeError("Documento JSON incompatible.")
    return obj


def _fields(obj: dict, fields: list, decoder=xor_java) -> dict:
    result = obj.copy()
    for field in obj.keys() & set(fields):
        # Nullable optional fields are preserved rather than replaced by UI defaults.
        if obj[field] is not None:
            result[field] = decoder(obj[field])
    return result


def _server(obj: dict) -> dict:
    return _fields(obj, NAMES["servers"])


def decode_catalog(data: bytes) -> dict:
    try:
        wire = shared._bounded(data).decode("utf-8-sig").strip().encode("ascii")
        match = re.fullmatch(rb"STGCM2\.TG\.([A-Za-z0-9_-]{16})\.([A-Za-z0-9_-]{22,})", wire)
        if not match:
            raise DecodeError("Sobre STGCM2.TG inválido.")
        nonce = shared._base64(match[1].decode(), urlsafe=True)
        raw = shared._base64(match[2].decode(), urlsafe=True)
        cipher = AES.new(CATALOG_KEY, AES.MODE_GCM, nonce=nonce)
        cipher.update(PREFIX)
        obj = _json(cipher.decrypt_and_verify(raw[:-16], raw[-16:]).decode("utf-8"))
        if not isinstance(obj.get("version"), str) or not obj["version"]:
            raise DecodeError("Versión de catálogo inválida.")
        result = _fields(obj, NAMES["root"])
        if "message" in obj:
            message = obj["message"]
            if not isinstance(message, str):
                raise DecodeError("Mensaje de catálogo inválido.")
            result["message"] = (shared._base64(message[3:]).decode("utf-8")
                if message.startswith("u8:") else xor_java(message))
        for group, fields in (("Servers", NAMES["servers"]), ("Tweaks", NAMES["tweaks"])):
            items = obj.get(group)
            if not isinstance(items, list) or any(not isinstance(e, dict) or not isinstance(e.get("Name"), str) for e in items):
                raise DecodeError("Lista de catálogo inválida.")
            result[group] = [_fields(entry, fields) for entry in items]
        shared._validate(result)
        return result
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise DecodeError("Catálogo inválido o no compatible con TunelGuard VPN 12.8.") from exc


def _double_base64(text: str) -> str:
    if not isinstance(text, str):
        raise DecodeError("Campo de perfil inválido.")
    if text == "":
        return ""
    return shared._base64(shared._base64(text).decode("ascii")).decode("utf-8")


def decode_profile(data: bytes) -> dict:
    try:
        wire = shared._bounded(data, MAX_FILE_BYTES).decode("utf-8-sig").strip()
        raw = shared._base64(wire)
        if len(raw) < 32 or len(raw) % 16:
            raise DecodeError("Perfil AES-CBC inválido.")
        plain = unpad(AES.new(FILE_KEY, AES.MODE_CBC, raw[:16]).decrypt(raw[16:]), 16)
        # JNI GetStringUTFChars/NewStringUTF use Modified UTF-8, including CESU-8
        # surrogate pairs. Android Base64 fields themselves use ordinary UTF-8.
        text = plain.replace(b"\xc0\x80", b"\0").decode("utf-8", "surrogatepass")
        text = text.encode("utf-16-le", "surrogatepass").decode("utf-16-le")
        obj = _json(text)
        profile = obj.get("TGV_CONFIG")
        if not isinstance(profile, dict) or type(profile.get("TunnelType")) is not int:
            raise DecodeError("El archivo no contiene TGV_CONFIG compatible.")
        decoded = _fields(profile, NAMES["profile"], _double_base64)
        if "Server" in profile:
            if not isinstance(profile["Server"], str):
                raise DecodeError("Servidor de perfil inválido.")
            if profile["Server"]:
                # Keep the original JSON-string type and every embedded key.
                decoded["Server"] = json.dumps(_server(_json(profile["Server"])), ensure_ascii=False, separators=(",", ":"))
        result = {**obj, "TGV_CONFIG": decoded}
        shared._validate(result)
        return result
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise DecodeError("Archivo inválido o no compatible con TunelGuard VPN 12.8.") from exc
