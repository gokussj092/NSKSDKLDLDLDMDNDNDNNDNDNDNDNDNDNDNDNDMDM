"""TunelGuard 17.7: STGCM3.TG catalog (v3 key), STGCM2/TGCR1 legacy envelopes,
and the native .tgv CBC profile.

Re-verified against build 177 (2026-11-27, tunnel.guard.vpn):

- Live catalog: GET https://raw.githubusercontent.com/guruzgh-ed/edd/refs/heads/main/tg.js
  (was https://raw.githubusercontent.com/eddyme23/octo/refs/heads/main/xxTG.js
  in 12.8, which no longer serves the catalog). STGCM3 envelope, version 5.0,
  config_revision 50, 90 servers, 1058 tweaks — verified live 2026-11-27.
- Envelope versions: v3 STGCM3 (live + bundled seed), v2 STGCM2 (12.8,
  kept), v1 TGCR1 (per-field credentials, kept). All three 32-byte keys are
  embedded-obfuscated blobs in libfrkudp.so, verified by GCM tag.
- Field values: TGCR1. -> v1 decrypt; u8: -> base64 UTF-8; otherwise the
  UTF-16 XOR obfuscation, applied only when the result reads as clean text.
- .tgv file decoder: HELD at the 12.8 native CBC profile (decode_profile
  below, unchanged). The 17.7 analysis found a Java STUC1 AES-GCM envelope
  class, but the real import/export path is native AES-128-CBC
  (TekProtect.nDecryptUserConfig/nEncryptUserConfig, libfrkudp.so), and no
  real .tgv file exported by 17.7 was available to decide between the two.
  Do NOT replace this decoder with the Java GCM format until a real
  exported .tgv sample is tested. See analysis/tunnel.guard.vpn/177/.

Keys below are fixed build parameters recovered from the app's own
library, not account/device credentials.
"""
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
# Envelope prefixes by version. v1 is TGCR1 (per-field credentials only);
# v2/v3 are STGCM catalog envelopes.
PREFIX = {1: b"TGCR1.", 2: b"STGCM2.TG.", 3: b"STGCM3.TG."}
KEYS = {
    1: bytes.fromhex("b7d6b2f7ff9988bd2c57de55002e1384ecdbf5e49ae64c46bd88c77aefdc0262"),
    2: bytes.fromhex("c09300e6f86c0e11c9bf709289481023d57655095bf2b7452204bb2e3d623ede"),
    3: bytes.fromhex("be5e019c282ee3789de4aaf2c5264ab1309dbb41f6c7f1e973677e1fc2f8cb22"),
}
# Backwards-compatible names: the 12.8 catalog key was the v2 key.
CATALOG_KEY = KEYS[3]
FILE_KEY = bytes.fromhex("5447565f555345525f43304e4631475f")
NAMES = json.loads(Path(__file__).with_name("field_names.json").read_text("utf-8"))

_XOR_MASKS = (30482, 14551, 22566, None)
_CJK = ((0x2E80, 0x9FFF), (0xAC00, 0xD7AF), (0xF900, 0xFAFF),
        (0xFF00, 0xFFEF), (0xE000, 0xF8FF), (0x20000, 0x2FFFF))


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


def _xor_utf16(text: str) -> str:
    """p64 XOR over UTF-16 code units (cycle 30482, 14551, 22566, ~)."""
    raw = text.encode("utf-16-be", "surrogatepass")
    units = [int.from_bytes(raw[i:i + 2], "big") for i in range(0, len(raw), 2)]
    out = []
    for i, unit in enumerate(units):
        mask = _XOR_MASKS[i % 4]
        out.append((~unit) & 0xFFFF if mask is None else unit ^ mask)
    return b"".join(u.to_bytes(2, "big") for u in out).decode("utf-16-be", "surrogatepass")


def _looks_clean(text: str) -> bool:
    for ch in text:
        code = ord(ch)
        if code < 0x20 and ch not in "\t\n\r":
            return False
        for low, high in _CJK:
            if low <= code <= high:
                return False
    return True


def _decrypt_envelope(wire: str, version: int) -> bytes:
    parts = wire.split(".")
    if version == 1:
        if len(parts) != 3 or parts[0] != "TGCR1":
            raise DecodeError("Sobre TGCR1 inválido.")
        nonce = shared._base64(parts[1], urlsafe=True)
        raw = shared._base64(parts[2], urlsafe=True)
    else:
        if len(parts) != 4 or parts[0] != "STGCM%d" % version or parts[1] != "TG":
            raise DecodeError("Sobre STGCM%d.TG inválido." % version)
        nonce = shared._base64(parts[2], urlsafe=True)
        raw = shared._base64(parts[3], urlsafe=True)
    if len(nonce) != 12 or len(raw) < 16:
        raise DecodeError("Sobre TunelGuard inválido.")
    cipher = AES.new(KEYS[version], AES.MODE_GCM, nonce=nonce)
    cipher.update(PREFIX[version])
    try:
        return cipher.decrypt_and_verify(raw[:-16], raw[-16:])
    except ValueError:
        raise DecodeError("El sobre TunelGuard no autentica.") from None


def decrypt_envelope(wire: str) -> bytes:
    """Decrypt an STGCM2/STGCM3/TGCR1 envelope; returns plaintext bytes."""
    text = wire.strip().lstrip("\ufeff")
    match = re.match(r"(?:STGCM(\d)|TGCR1)", text)
    if not match:
        raise DecodeError("Sobre TunelGuard inválido.")
    version = 1 if match.group(0) == "TGCR1" else int(match.group(1))
    if version not in KEYS:
        raise DecodeError("Versión de sobre TunelGuard no compatible.")
    return _decrypt_envelope(text, version)


def _field(value):
    """Decode one catalog field value (p64.O00oO0o / MainActivity.b1)."""
    if not isinstance(value, str):
        return value
    if value.startswith("TGCR1."):
        return _decrypt_envelope(value, 1).decode("utf-8")
    if value.startswith("u8:"):
        return shared._base64(value[3:]).decode("utf-8")
    if value and any(ord(c) > 127 for c in value):
        candidate = _xor_utf16(value)
        if _looks_clean(candidate):
            return candidate
    return value


def _deep_fields(obj):
    if isinstance(obj, dict):
        return {key: _deep_fields(item) for key, item in obj.items()}
    if isinstance(obj, list):
        return [_deep_fields(item) for item in obj]
    if isinstance(obj, str):
        return _field(obj)
    return obj


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
        wire = shared._bounded(data).decode("utf-8-sig").strip()
        obj = _json(decrypt_envelope(wire).decode("utf-8"))
        if not isinstance(obj.get("version"), str) or not obj["version"]:
            raise DecodeError("Versión de catálogo inválida.")
        result = _deep_fields(obj)
        # The result JSON carries catalog data only, never the download API.
        result.pop("url_updater", None)
        for group in ("Servers", "Tweaks"):
            items = obj.get(group)
            if not isinstance(items, list) or any(not isinstance(e, dict) or not isinstance(e.get("Name"), str) for e in items):
                raise DecodeError("Lista de catálogo inválida.")
        shared._validate(result)
        return result
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise DecodeError("Catálogo inválido o no compatible con TunelGuard VPN 17.7.") from exc


def _double_base64(text: str) -> str:
    if not isinstance(text, str):
        raise DecodeError("Campo de perfil inválido.")
    if text == "":
        return ""
    return shared._base64(shared._base64(text).decode("ascii")).decode("utf-8")


def decode_profile(data: bytes) -> dict:
    """Native .tgv CBC profile (12.8 format, HELD for 17.7 — see module docstring).

    Base64 text: first 16 bytes are the IV, the rest is AES-128-CBC with the
    16-byte master key. Unverified against a real 17.7 export; a real
    exported .tgv sample is still needed to confirm the format/key.
    """
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
