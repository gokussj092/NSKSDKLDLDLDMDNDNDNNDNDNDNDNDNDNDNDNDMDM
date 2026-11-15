"""APK-derived Tunneltweak builds 51/53 profiles and SecureConfigEncryption catalogs."""
from __future__ import annotations
import base64
import hashlib
import json
import math
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

MAX_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 5 * 1024 * 1024
FILE_KEY = b"TunnelTweak2024!"
CATALOG_PASSWORD = "TunnelTweak-Secure-v1"
PBE_PREFIX = "TTPBE1:"


class DecodeError(ValueError):
    """Sanitized failure; never includes input, password or decrypted fields."""


class PasswordRequired(DecodeError):
    def __init__(self):
        super().__init__("PASSWORD_REQUIRED")


class AuthFailed(DecodeError):
    def __init__(self):
        super().__init__("AUTH_FAILED")


def bounded(data: bytes, limit=MAX_BYTES) -> bytes:
    if not isinstance(data, bytes) or not data or len(data) > limit:
        raise DecodeError("Entrada vacía o superior al límite permitido.")
    return data


def b64(text: str) -> bytes:
    raw = "".join(text.split()).encode("ascii")
    if not raw or len(raw) % 4 == 1:
        raise DecodeError("Base64 inválido.")
    return base64.b64decode(raw + b"=" * (-len(raw) % 4), validate=True)


def _unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise DecodeError("JSON con claves duplicadas.")
        obj[key] = value
    return obj


def _constant(_value):
    raise DecodeError("JSON con números no finitos.")


def validate(value, depth=0):
    if depth > 64:
        raise DecodeError("Profundidad superior a 64.")
    if isinstance(value, dict):
        for key, item in value.items():
            key.encode("utf-8")
            validate(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            validate(item, depth + 1)
    elif isinstance(value, str):
        value.encode("utf-8")
    elif isinstance(value, float) and not math.isfinite(value):
        raise DecodeError("Número fuera del rango JSON.")


def parse(text: str) -> dict:
    value = json.loads(text, object_pairs_hook=_unique, parse_constant=_constant)
    validate(value)
    if not isinstance(value, dict) or not value:
        raise DecodeError("Se esperaba un objeto JSON completo.")
    return value


def _password(value: str) -> bytes:
    if not isinstance(value, str) or not 0 < len(value) <= 4096:
        raise DecodeError("Contraseña vacía o superior al límite permitido.")
    return value.encode("utf-8")


def gcm(raw: bytes, password: str, rounds: int) -> str:
    if len(raw) < 44:
        raise DecodeError("Sobre AES-GCM truncado.")
    key = hashlib.pbkdf2_hmac("sha256", _password(password), raw[:16], rounds, 32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=raw[16:28], mac_len=16)
    return cipher.decrypt_and_verify(raw[28:-16], raw[-16:]).decode("utf-8")


def decode_profile(data: bytes, *, password: str | None = None) -> dict:
    try:
        text = bounded(data, MAX_FILE_BYTES).decode("utf-8-sig").strip()
        if text.startswith(PBE_PREFIX):
            raw = b64(text[len(PBE_PREFIX):])
            if len(raw) < 44:
                raise DecodeError("Sobre TTPBE1 truncado.")
            if password is None:
                raise PasswordRequired()
            try:
                clear = gcm(raw, password, 120000)
            except (ValueError, UnicodeError) as exc:
                raise AuthFailed() from exc
        else:
            raw = b64(text)
            clear = None
            # This APK tries CBC first, then its explicit XOR-90 legacy reader.
            # No fallback is reachable from a TTPBE1 authentication failure.
            if len(raw) >= 32 and len(raw) % 16 == 0:
                try:
                    clear = unpad(AES.new(FILE_KEY, AES.MODE_CBC, raw[:16]).decrypt(raw[16:]), 16).decode("utf-8")
                except (ValueError, UnicodeError):
                    pass
            if clear is None:
                clear = bytes(x ^ 90 for x in raw).decode("utf-8")
        obj = parse(clear)
        if type(obj.get("config_version")) is not int or obj["config_version"] != 6:
            raise DecodeError("Versión de archivo incompatible; se esperaba config_version 6.")
        # Do not remove config_version/message, reset expiry, coerce values or
        # apply Android device/root policies: this reader returns the source JSON.
        return obj
    except (PasswordRequired, AuthFailed):
        raise
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        raise DecodeError("Archivo inválido o no compatible con Tunneltweak.") from exc


def _catalog_blob(text: str, api_key: str | None) -> dict:
    if text.lstrip().startswith("{"):
        return parse(text)
    raw = b64(text)
    # Explicit older Base64(JSON) format. Invalid GCM never retries this format.
    if raw.lstrip().startswith(b"{"):
        try:
            return parse(raw.decode("utf-8"))
        except (ValueError, UnicodeError, RecursionError):
            # A random GCM salt can also begin with a JSON brace.
            pass
    passwords = [CATALOG_PASSWORD] if api_key is None else [api_key, CATALOG_PASSWORD]
    for password in dict.fromkeys(passwords):
        try:
            clear = gcm(raw, password, 10000)
        except (ValueError, UnicodeError):
            continue
        return parse(clear)
    raise DecodeError("No se pudo autenticar el catálogo con las claves proporcionadas.")


def decode_catalog(data: bytes, *, api_key: str | None = None) -> dict:
    try:
        text = bounded(data).decode("utf-8-sig").strip()
        outer = parse(text) if text.startswith("{") else None
        if outer is not None and "data" in outer:
            if not isinstance(outer["data"], str):
                raise DecodeError("Sobre data incompatible.")
            obj = _catalog_blob(outer["data"], api_key)
            result = dict(outer, data=obj)
        else:
            obj = _catalog_blob(text, api_key)
            result = obj
        if not isinstance(obj.get("servers"), list) or not isinstance(obj.get("configs"), dict):
            raise DecodeError("Estructura de catálogo incompatible.")
        if not obj["servers"] and not obj["configs"]:
            raise DecodeError("El catálogo no contiene perfiles.")
        if any(not isinstance(item, dict) or not item for item in obj["servers"]):
            raise DecodeError("Lista de servidores incompatible.")
        if any(not isinstance(item, dict) or not item for item in obj["configs"].values()):
            raise DecodeError("Configuraciones incompatibles.")
        validate(result)
        # Preserve the outer announcement/metadata, invisible servers, tiers,
        # config IDs and unknown fields. Models in the APK discard some of them.
        return result
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        raise DecodeError("Catálogo inválido o no compatible con Tunneltweak.") from exc


def render(value) -> str:
    validate(value)
    text = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise DecodeError("La salida supera 8 MiB.")
    return text

