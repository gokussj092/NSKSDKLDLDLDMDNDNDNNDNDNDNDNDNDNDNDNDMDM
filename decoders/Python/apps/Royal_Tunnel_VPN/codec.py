"""Royal Tunnel VPN 7.0 formats, recovered from this APK's Java and wg-pro.

No historical Royal/XTProy codecs, APK, native library or network at runtime.
"""
from __future__ import annotations

import base64
import json
import math
import struct

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

MAX_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 64
BRAND = b"Royal Tunnel VPN"
NATIVE_KEY = bytes.fromhex("0123456789abcdef1032547698badcfe554433221100aabbccddeeff99887766")
CFB_KEY = bytes.fromhex("974f2a3d5e5c0d50ca2c3e8aae1c4f79ddccf43cef90f9984a7e09fdc09bc482")
CFB_IV = bytes.fromhex("4e6a2c8153d9b4a7903f685ca1ef2479")
CATALOG_KEY = bytes.fromhex("e385a4e385a4e385a4e385a4e385a4e3")
DELTA = (-1703701580) & 0xffffffff
MASK = 0xffffffff
# Tweak key/IV derive from AbstractC4679uE0.e/h, independently of CFB.
TWEAK_KEY = bytes.fromhex("6438383065643332393166393664393436346132633933356538323938333766")
TWEAK_IV = bytes.fromhex("3c7f1a9d55e3c0b28e216d4a97ff1362")
PROFILE_FIELDS = frozenset({
    "Payload", "SNIHost", "ProxyHost", "ProxyPort", "DNSHost", "UDPhost",
    "UDPobfs", "UDPauth", "UDPUpMbps", "UDPDownMbps", "UDPPort",
    "v2rayConfig", "v2raySni", "WireGuardConfig",
})
ROOT_FIELDS = frozenset({
    "Version", "Message", "DefUpdateURL", "updater", "updatemsg", "Banner_ID",
    "AppOpenAd", "Interstitial_ID", "RewardAd_ID", "RewardInter_ID",
    "cardMessage", "cardLink",
})
SERVER_FIELDS = frozenset({
    "Name", "Flag", "Info", "ServerIPHost", "ServerHTTPHost", "TCPPort",
    "SSLPort", "DropBear", "ProxyPort", "PrivateKey", "Username", "Password",
    "OpenVPNUDPPort", "OpenVPNCertificate",
})
SERVER_GROUPS = {
    "WireGuard": frozenset({"WGConfig"}),
    "UDP": frozenset({"UDPOpenPort", "UDPObfs"}),
    "SlowDNS": frozenset({"DNSTTNS", "DNSTTKey"}),
    "V2ray": frozenset({"UUID", "Path"}),
}
TWEAK_FIELDS = frozenset({
    "Name", "Info", "Payload", "Sni", "ProxyHost", "ProxyPort", "DNSHost",
    "UDPupMbps", "UDPdownMbps", "UDPrecvw", "v2rayjson", "v2Sni",
})


class DecodeError(ValueError):
    """Messages never contain input values, credentials or remote bodies."""


def base64_bytes(value: str) -> bytes:
    try:
        compact = "".join(value.split()).encode("ascii")
        if not compact or len(compact) % 4 == 1:
            raise ValueError
        return base64.b64decode(compact + b"=" * (-len(compact) % 4), validate=True)
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("Base64 inválido.") from exc


def decrypt_gcm(value: str) -> str:
    if value == "":
        return ""
    try:
        raw = base64_bytes(value)
        if len(raw) < 28:
            raise ValueError
        aes = AES.new(NATIVE_KEY, AES.MODE_GCM, nonce=raw[:12], mac_len=16)
        return aes.decrypt_and_verify(raw[12:-16], raw[-16:]).decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("Campo de perfil incompatible o etiqueta GCM inválida.") from exc


def decrypt_cfb(value: str) -> str:
    if value == "":
        return ""
    try:
        aes = AES.new(CFB_KEY, AES.MODE_CFB, iv=CFB_IV, segment_size=128)
        return aes.decrypt(base64_bytes(value)).decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("Campo de servidor o metadatos incompatible.") from exc


def decrypt_tweak(value: str) -> str:
    if value == "":
        return ""
    try:
        aes = AES.new(TWEAK_KEY, AES.MODE_CBC, iv=TWEAK_IV)
        return unpad(aes.decrypt(base64_bytes(value)), 16).decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("Campo de tweak incompatible.") from exc


def _mix(total, y, z, position, e, key):
    return ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^
            ((total ^ y) + (key[(position & 3) ^ e] ^ z))) & MASK


def decrypt_xxtea(data: bytes) -> bytes:
    if len(data) < 8 or len(data) % 4:
        raise DecodeError("Bloques XXTEA incompletos.")
    words = list(struct.unpack("<%dI" % (len(data) // 4), data))
    key = struct.unpack("<4I", CATALOG_KEY)
    rounds = 6 + 52 // len(words)
    total, y = (rounds * DELTA) & MASK, words[0]
    for _ in range(rounds):
        e = (total >> 2) & 3
        for position in range(len(words) - 1, 0, -1):
            words[position] = (words[position] - _mix(total, y, words[position-1], position, e, key)) & MASK
            y = words[position]
        words[0] = (words[0] - _mix(total, y, words[-1], 0, e, key)) & MASK
        y = words[0]
        total = (total - DELTA) & MASK
    size = words[-1]
    if not len(data) - 7 <= size <= len(data) - 4:
        raise DecodeError("Longitud XXTEA inválida.")
    return struct.pack("<%dI" % len(words), *words)[:size]


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DecodeError("JSON con claves duplicadas.")
        result[key] = value
    return result


def _reject_constant(_value):
    raise DecodeError("Número JSON no finito.")


def _validate(value, depth=0):
    if depth > MAX_DEPTH:
        raise DecodeError("Profundidad JSON superior a 64.")
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


def _json(data: bytes | str) -> dict:
    obj = json.loads(data, object_pairs_hook=_unique, parse_constant=_reject_constant)
    if not isinstance(obj, dict):
        raise DecodeError("Se esperaba un objeto JSON.")
    _validate(obj)
    return obj


def _input(data: bytes) -> str:
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError("Entrada vacía o superior a 8 MiB.")
    return data.decode("utf-8-sig").strip()


def _fields(obj: dict, names, decrypt) -> dict:
    result = obj.copy()
    for name in names & obj.keys():
        if not isinstance(obj[name], str):
            raise DecodeError("Un campo cifrado no contiene texto.")
        result[name] = decrypt(obj[name])
    return result


def decode_server(obj: dict) -> dict:
    result = _fields(obj, SERVER_FIELDS, decrypt_cfb)
    for group, names in SERVER_GROUPS.items():
        if group in obj:
            if not isinstance(obj[group], dict):
                raise DecodeError("Grupo de servidor incompatible.")
            result[group] = _fields(obj[group], names, decrypt_cfb)
    return result


def decode_profile(data: bytes) -> dict:
    try:
        raw = base64_bytes(_input(data))
        if len(raw) < 32 or len(raw) % 16:
            raise DecodeError("Bloques del archivo .roy incompletos.")
        plain = unpad(AES.new(NATIVE_KEY, AES.MODE_CBC, iv=raw[:16]).decrypt(raw[16:]), 16)
        if not plain.startswith(BRAND):
            raise DecodeError("El archivo no pertenece a Royal Tunnel VPN 7.0.")
        obj = _json(plain[len(BRAND):].decode("utf-8"))
        if (type(obj.get("NoobDev")) is not int or obj["NoobDev"] != 7 or
                type(obj.get("TunnelType")) is not int or not 0 <= obj["TunnelType"] <= 10 or
                not PROFILE_FIELDS <= obj.keys() or "Servers" in obj or "Tweaks" in obj):
            raise DecodeError("Estructura de perfil Royal 7.0 incompatible.")
        result = _fields(obj, PROFILE_FIELDS, decrypt_gcm)
        if "Server" in obj:
            if not isinstance(obj["Server"], str):
                raise DecodeError("El servidor incluido debe ser una cadena JSON.")
            if obj["Server"]:
                # The exporter stores a JSON *string*: preserve that value type.
                server = decode_server(_json(obj["Server"]))
                result["Server"] = json.dumps(server, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        _validate(result)
        return result
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("Archivo .roy inválido, corrupto o de otra versión.") from exc


def decode_catalog(data: bytes) -> dict:
    try:
        obj = _json(decrypt_xxtea(base64_bytes(_input(data))).decode("utf-8"))
        if (not isinstance(obj.get("Version"), str) or not obj["Version"] or
                any(not isinstance(obj.get(k), list) for k in ("Servers", "Tweaks")) or
                not (obj["Servers"] or obj["Tweaks"])):
            raise DecodeError("Estructura del catálogo incompatible.")
        for section in ("Servers", "Tweaks"):
            if any(not isinstance(item, dict) or not isinstance(item.get("Name"), str) for item in obj[section]):
                raise DecodeError("Elemento de catálogo incompatible.")
        result = _fields(obj, ROOT_FIELDS, decrypt_cfb)
        result["Servers"] = [decode_server(item) for item in obj["Servers"]]
        result["Tweaks"] = [_fields(item, TWEAK_FIELDS, decrypt_tweak) for item in obj["Tweaks"]]
        _validate(result)
        return result
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("Catálogo Royal 7.0 inválido o incompatible.") from exc


def render(obj: dict) -> str:
    result = json.dumps(obj, ensure_ascii=False, indent=2, allow_nan=False)
    if len(result.encode("utf-8")) > MAX_BYTES:
        raise DecodeError("La salida supera 8 MiB.")
    return result
