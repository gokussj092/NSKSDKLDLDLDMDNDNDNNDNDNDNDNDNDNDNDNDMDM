"""AustroPlus VPN 13.0.1: APK-verified GCM profiles and XXTEA/XOR catalogs."""
from __future__ import annotations

import base64
import json
import math
from pathlib import Path
import sys

# Reuse the unchanged standard-XXTEA primitive, with this APK's verified key.
try:
    from decoders.Python import ec
except ModuleNotFoundError:
    root = next((p for p in Path(__file__).resolve().parents
                 if (p / "decoders/Python/ec.py").is_file()), None)
    if root is not None:
        sys.path.insert(0, str(root))
        from decoders.Python import ec
    else:
        import ec

MAX_BYTES = 8 * 1024 * 1024
MAX_PROFILE_BYTES = 5 * 1024 * 1024
MAX_DEPTH = 64
PROFILE_KEY = b"AustroPlus-VPN-File-Secret-Key-!"
CATALOG_KEY = b"AustroPlusVPN_GenPass@2244"
XOR_KEY = b"BaseZh"
PROFILE_FIELDS = frozenset({
    "CFGMessage", "MyPass", "Payload", "SNIHost", "BUGHost", "DNSHost", "V2RAYLink",
    "UDPIP", "UDPPorts", "UDPObfs", "UDPAuth", "ProxySet", "Server",
})
SERVER_FIELDS = frozenset({
    "SSHHost", "WebServer", "PublicKey", "NameServer", "Username", "Password",
    "DNSUsername", "DNSPassword", "WebUser", "WebPass",
})
TWEAK_FIELDS = frozenset({"ProxyHost", "Payload", "Bug", "Sni", "DNSHost"})
CATALOG15_SERVER_FIELDS = frozenset({
    "server_host", "username", "password", "udp_host", "udp_obf", "udp_auth",
    "dns_pubkey", "name_server", "dns_user", "dns_pass", "v2uuid", "v2_host", "v2path",
    "cf_server", "cf_user", "cf_pass", "ws_host", "ws_user", "ws_pass", "wireguard",
})
CATALOG15_TWEAK_FIELDS = frozenset({
    "proxy_host", "custom_payload", "custom_bug", "custom_sni", "custom_dns", "custom_v2_sni", "custom_v2ray",
})


class DecodeError(ValueError):
    """Sanitized failure: no input, credentials or provider response in messages."""


def _base64(value: str, *, empty=False) -> bytes:
    try:
        if not isinstance(value, str):
            raise ValueError
        compact = "".join(value.split()).encode("ascii")
        if not compact and empty:
            return b""
        if not compact or len(compact) % 4 == 1:
            raise ValueError
        return base64.b64decode(compact + b"=" * (-len(compact) % 4), validate=True)
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("Base64 inválido.") from exc


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DecodeError("JSON con claves duplicadas.")
        result[key] = value
    return result


def _reject_constant(_value):
    raise DecodeError("JSON con números no finitos.")


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


def _json(text: str) -> dict:
    obj = json.loads(text, object_pairs_hook=_unique, parse_constant=_reject_constant)
    if not isinstance(obj, dict) or not obj:
        raise DecodeError("Se esperaba un objeto JSON no vacío.")
    _validate(obj)
    return obj


def _input(data: bytes, limit=MAX_BYTES) -> str:
    if not isinstance(data, bytes) or not data or len(data) > limit:
        raise DecodeError("Entrada vacía o superior al límite permitido.")
    return data.decode("utf-8-sig").strip()


def double_base64(value: str) -> str:
    """wc0.k: two Android DEFAULT Base64 layers, including empty strings."""
    return _base64(_base64(value, empty=True).decode("ascii"), empty=True).decode("utf-8")


def xor_field(value: str) -> str:
    """ys.h / MainActivity.Y: Base64 then repeating six-byte XOR."""
    raw = _base64(value, empty=True)
    return bytes(byte ^ XOR_KEY[i % len(XOR_KEY)] for i, byte in enumerate(raw)).decode("utf-8")


def _fields(obj: dict, names, decode) -> dict:
    result = obj.copy()
    for key in names & obj.keys():
        if not isinstance(obj[key], str):
            raise DecodeError("Un campo codificado no contiene texto.")
        result[key] = decode(obj[key])
    return result


def decrypt_profile(text: str) -> str:
    # Catalog-only use remains standard-library-only; AES is needed for files.
    from Crypto.Cipher import AES
    raw = _base64(text)
    if len(raw) < 28:
        raise DecodeError("Sobre AES-GCM incompleto.")
    cipher = AES.new(PROFILE_KEY, AES.MODE_GCM, nonce=raw[:12], mac_len=16)
    try:
        return cipher.decrypt_and_verify(raw[12:-16], raw[-16:]).decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("Archivo incompatible o etiqueta AES-GCM inválida.") from exc


def decode_profile(data: bytes) -> dict:
    try:
        obj = _json(decrypt_profile(_input(data, MAX_PROFILE_BYTES)))
        if not isinstance(obj.get("CONFIG"), dict) or not obj["CONFIG"]:
            raise DecodeError("El archivo no contiene CONFIG.")
        result = obj.copy()
        config = _fields(obj["CONFIG"], PROFILE_FIELDS, double_base64)
        if config.get("Server"):
            server = _fields(_json(config["Server"]), SERVER_FIELDS, xor_field)
            # The original export stores Server as JSON text, not as an object.
            config["Server"] = json.dumps(server, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        result["CONFIG"] = config
        _validate(result)
        return result
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("Formato de archivo inválido o no compatible.") from exc


def decode_catalog(data: bytes) -> dict:
    try:
        raw = _base64(_input(data))
        plain = ec._decrypt_xxtea(raw, CATALOG_KEY)
        if plain is None:
            raise DecodeError("Bloques o longitud XXTEA inválidos.")
        obj = _json(plain.decode("utf-8"))
        if (not isinstance(obj.get("version"), str) or not obj["version"] or
                any(not isinstance(obj.get(k), list) for k in ("Servers", "Tweaks")) or
                not (obj["Servers"] or obj["Tweaks"]) or
                any(not isinstance(item, dict) or not (isinstance(item.get("Name"), str) or isinstance(item.get("name"), str))
                    for k in ("Servers", "Tweaks") for item in obj[k])):
            raise DecodeError("Estructura de catálogo incompatible.")
        result = _fields(obj, frozenset({"url_updater"}), xor_field)
        result["Servers"] = [_fields(item, SERVER_FIELDS if isinstance(item.get("Name"),str) else CATALOG15_SERVER_FIELDS, xor_field) for item in obj["Servers"]]
        result["Tweaks"] = [_fields(item, TWEAK_FIELDS if isinstance(item.get("Name"),str) else CATALOG15_TWEAK_FIELDS, xor_field) for item in obj["Tweaks"]]
        _validate(result)
        return result
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("Formato de catálogo inválido o no compatible.") from exc


def render(value) -> str:
    text = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise DecodeError("La salida supera 8 MiB.")
    return text
