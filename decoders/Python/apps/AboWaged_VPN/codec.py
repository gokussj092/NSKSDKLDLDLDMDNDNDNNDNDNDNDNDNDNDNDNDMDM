"""AboWaged VPN 1.0 formats, confirmed from its DEX and ARM64 JNI wrappers.

Offline only. Custom catalog XXTEA, catalog/server CBC, exported-profile CBC,
profile-field CFB128, and the separate UDP picker's decimal UTF-16 strings.
Passwords in MyPass are application locks, never input to these ciphers.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import struct

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

MAX_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 64
MASK = 0xffffffff
CATALOG_DELTA = (-1703701580) & MASK
# Literal string, NOT the Java expression it resembles. Dalvik truncates to 16.
CATALOG_KEY = b"new String(new byte[]{72,101,120,88,86,80,78,80,97,115,115})"[:16]
FIELD_IV = bytes.fromhex("0123456789abcdef1032547698badcfe")
# Shared format constants from libwg-pro.so, not caller/device credentials.
J_KEY = hashlib.sha256(
    b"AESCBCcrptor;Java/com/jztunnel_vpn_libandroid.so_:crypto_NativeCrypto/"
    b"Fdecrypt/(Ljava/lang/String;Ljava/lang/Strin"
).digest()
F_KEY = hashlib.sha256(
    b"(Ljava/lang/String;Ljava/lang/String)https://;t.me/noobdev24"
).digest()

ROOT_FIELDS = frozenset({
    "Version", "Message", "DefUpdateURL", "updater", "updatemsg", "Banner_ID",
    "AppOpenAd", "Interstitial_ID", "RewardAd_ID", "RewardInter_ID", "cardMessage",
    "cardLink",
})
SERVER_FIELDS = frozenset({
    "SSHHost", "Category", "SSHPort", "SSLPort", "DropBear", "ProxyPort",
    "Username", "Password", "UDPServer", "Obfs", "Auth", "CFServer", "CFUser",
    "CFPass", "vuid", "vhost", "vpath", "wgConf", "vprotocol", "NameServer",
    "PublicKey", "DNSUsername", "DNSPassword", "WebServer", "WebUser", "WebPass",
})
TWEAK_FIELDS = frozenset({
    "DNSHost", "Payload", "Sni", "ProxyHost", "ProxyPort", "v2Sni", "vport",
    "v2rayjson", "Bug",
})
PROFILE_FIELDS = frozenset({
    "Payload", "WSPayload", "SNIHost", "BUGHost", "DNSHost", "ProxySet",
    "UDPhost", "UDPobfs", "UDPauth", "V2Ejson", "v2Esni", "EwgConf",
})


class DecodeError(ValueError):
    """Sanitized errors, without plaintext, ciphertext or credential values."""


def _base64(value: str) -> bytes:
    try:
        compact = re.sub(r"[ \t\r\n]", "", value).encode("ascii")
        if not compact or len(compact) > MAX_BYTES or len(compact) % 4:
            raise ValueError
        return base64.b64decode(compact, validate=True)
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("Base64 inválido.") from exc


def _input(data: bytes) -> str:
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError("Entrada vacía o superior a 8 MiB.")
    try:
        return data.decode("utf-8-sig").strip()
    except UnicodeError as exc:
        raise DecodeError("Entrada UTF-8 inválida.") from exc


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DecodeError("Claves JSON duplicadas.")
        result[key] = value
    return result


def _constant(_value):
    raise DecodeError("Número JSON no finito.")


def _validate(value):
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > MAX_DEPTH or count > 1_000_000:
            raise DecodeError("Complejidad JSON superior al límite.")
        if isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
            pending.extend((k, depth + 1) for k in item)
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
        elif isinstance(item, float) and not math.isfinite(item):
            raise DecodeError("Número JSON fuera de rango.")
        elif isinstance(item, str):
            item.encode("utf-8")
    return value


def _json(data):
    try:
        return _validate(json.loads(data, object_pairs_hook=_unique, parse_constant=_constant))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("JSON inválido.") from exc


def decrypt_catalog_bytes(data: bytes) -> bytes:
    """Original Dalvik variant: LE words, custom delta, last-word length."""
    raw = _base64(_input(data))
    if len(raw) < 8 or len(raw) % 4:
        raise DecodeError("Bloques XXTEA inválidos.")
    values = list(struct.unpack(f"<{len(raw) // 4}I", raw))
    key = struct.unpack("<4I", CATALOG_KEY)
    rounds = 6 + 52 // len(values)
    total, y = (rounds * CATALOG_DELTA) & MASK, values[0]

    def mx(y, z, position, e):
        return ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^
                ((total ^ y) + (key[(position & 3) ^ e] ^ z))) & MASK

    for _ in range(rounds):
        e = (total >> 2) & 3
        for position in range(len(values) - 1, 0, -1):
            values[position] = (values[position] - mx(y, values[position - 1], position, e)) & MASK
            y = values[position]
        values[0] = (values[0] - mx(y, values[-1], 0, e)) & MASK
        y = values[0]
        total = (total - CATALOG_DELTA) & MASK
    size = values[-1]
    if not len(raw) - 7 <= size <= len(raw) - 4:
        raise DecodeError("Longitud XXTEA inválida.")
    return struct.pack(f"<{len(values)}I", *values)[:size]


def _aes(value: str, key: bytes, *, cfb=False, iv=FIELD_IV) -> str:
    if value == "":
        return ""
    try:
        raw = _base64(value)
        if cfb:
            plain = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(raw)
        else:
            if not raw or len(raw) % 16:
                raise ValueError
            plain = unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(raw), 16)
        return plain.decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("Contenido cifrado incompatible.") from exc


def decrypt_j(value: str) -> str:
    return _aes(value, J_KEY)


def decrypt_f(value: str) -> str:
    return _aes(value, F_KEY, cfb=True)


def _fields(obj, names, method):
    result = dict(obj)
    for key in names:
        if key not in obj or obj[key] is None:
            continue
        if not isinstance(obj[key], str):
            raise DecodeError("Campo cifrado de tipo incompatible.")
        result[key] = method(obj[key])
    return result


def decode_catalog(data: bytes) -> dict:
    obj = _json(decrypt_catalog_bytes(data))
    if (not isinstance(obj, dict) or not isinstance(obj.get("Version"), str) or
            any(not isinstance(obj.get(k), list) for k in ("Servers", "Tweaks")) or
            not (obj["Servers"] or obj["Tweaks"])):
        raise DecodeError("Esquema de catálogo incompatible.")
    result = _fields(obj, ROOT_FIELDS, decrypt_j)
    for section, fields in (("Servers", SERVER_FIELDS), ("Tweaks", TWEAK_FIELDS)):
        if any(not isinstance(item, dict) or not isinstance(item.get("Name"), str)
               for item in obj[section]):
            raise DecodeError("Registro de catálogo incompatible.")
        result[section] = [_fields(item, fields, decrypt_j) for item in obj[section]]
    return _validate(result)


def _profile_key() -> bytes:
    seed = hashlib.sha256(b"C3sNbUKg92mKwhxQObxKpA==").digest()
    text = _aes("lQ+t8x63PO1wN4B7vFjgfA==", seed, iv=bytes(16))
    return hashlib.sha256(text.encode("utf-8")).digest()


def decode_file(data: bytes) -> dict:
    obj = _json(_aes(_input(data), _profile_key(), iv=bytes(16)))
    if (not isinstance(obj, dict) or "Servers" in obj or "Tweaks" in obj or
            type(obj.get("NoobDev")) is not int or type(obj.get("TunnelType")) is not int or
            not isinstance(obj.get("Payload"), str) or
            not isinstance(obj.get("isPassON"), bool) or not isinstance(obj.get("MyPass"), str)):
        raise DecodeError("Esquema de archivo .awg incompatible.")
    result = _fields(obj, PROFILE_FIELDS, decrypt_f)
    if "Server" in obj and obj["Server"] is not None:
        if not isinstance(obj["Server"], str):
            raise DecodeError("Servidor exportado de tipo incompatible.")
        if obj["Server"]:
            server = _json(obj["Server"])
            if not isinstance(server, dict):
                raise DecodeError("Servidor exportado incompatible.")
            # Keep the original string type; decode its APK-proven JSON members.
            result["Server"] = json.dumps(_fields(server, SERVER_FIELDS, decrypt_j),
                                        ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return _validate(result)


def _decimal_chars(text: str) -> str:
    if not isinstance(text, str) or len(text) > MAX_BYTES:
        raise DecodeError("Cadena UDP inválida.")
    try:
        parts = text.rstrip(",").split(",")  # Java String.split drops trailing empties.
        if any(not re.fullmatch(r"[+-]?[0-9]{1,11}", p) for p in parts):
            raise ValueError
        values = [int(p) for p in parts]
        if any(not -2147483648 <= v <= 2147483647 for v in values):
            raise ValueError
        return b"".join(struct.pack("<H", v & 65535) for v in values).decode("utf-16-le")
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("Cadena decimal UTF-16 incompatible.") from exc


def decode_udp(data: bytes) -> list:
    obj = _json(_input(data))
    if not isinstance(obj, list) or not obj or any(
            not isinstance(v, dict) or not isinstance(v.get("UDPserver"), str) or
            any(not isinstance(v.get(k), str) for k in ("obfs", "auth")) for v in obj):
        raise DecodeError("Esquema UDP incompatible.")
    return [_fields(v, {"obfs", "auth"}, _decimal_chars) for v in obj]


def render(value) -> str:
    try:
        text = json.dumps(_validate(value), ensure_ascii=False, indent=2, allow_nan=False)
        if len(text.encode("utf-8")) > MAX_BYTES:
            raise DecodeError("Salida superior a 8 MiB.")
        return text
    except (UnicodeError, RecursionError) as exc:
        raise DecodeError("JSON de salida inválido.") from exc
