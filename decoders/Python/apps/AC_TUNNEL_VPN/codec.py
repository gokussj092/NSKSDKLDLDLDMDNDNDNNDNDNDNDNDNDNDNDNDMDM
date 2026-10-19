"""AC TUNNEL VPN 1.4 formats verified against its original ARM64 primitives."""
from __future__ import annotations

import base64
from functools import lru_cache
import hashlib
import json
import math
from pathlib import Path
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# The download bundle carries this exact existing primitive module as renz.py.
try:
    from decoders.Python import renz
except ModuleNotFoundError:
    root = next((p for p in Path(__file__).resolve().parents
                 if (p / "decoders/Python/renz.py").is_file()), None)
    if root is not None:
        sys.path.insert(0, str(root))
        from decoders.Python import renz
    else:
        import renz

MAX_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 64
PROFILE_PREFIX = "actunnelvpn://"
REFERENCE_PREFIX = "acvpn://"
SEED = bytes.fromhex("3df2206048b6a96899c64cbd244ca4b94e4f63d816c9e61ab5af526181891e82")
SALT = bytes.fromhex("896a673b34f9c9832a3e0f63060fb990abafe2bffc58f5944747fcfdf63c697b")
IV = bytes.fromhex("81cc11ecac729b67e54c9f087520e1d4")
MAIN_KEY = hashlib.sha256(SEED).digest()[:16]
MAIN_FIELDS = frozenset({
    "Name", "Subname", "Info", "flag", "OpenVPNTCPPort", "OpenVPNSSLPort",
    "UDPSSLPort", "CloudfrontDNS", "Obfs", "CustomCert", "DNSResolver", "TLSVersion",
})
SPECIAL_FIELDS = frozenset({"ServerIPHost", "SNIHost", "Payload"})
SENSITIVE_FIELDS = frozenset({"Username", "Password"})
# Only APK-proven locations are decrypted. Unknown objects/strings stay intact.
CHILD_FIELDS = {
    "SlowDNS": ({"NSNameServer", "PubKey"}, set()),
    "V2Ray": ({"UUID"}, {"PATH", "V2RayHost", "SNIHost", "CustomV2RAYConfig"}),
    "UDPOptions": ({"UpMbps", "DlMbps", "RecvConnectionWindow"}, set()),
    "ProxySettings": ({"Squid", "Port"}, set()),
}


class DecodeError(ValueError):
    """A sanitized failure without any input values or credentials."""


def _base64(text: str) -> bytes:
    try:
        compact = "".join(text.split()).encode("ascii")
        if not compact or len(compact) % 4 == 1:
            raise ValueError
        return base64.b64decode(compact + b"=" * (-len(compact) % 4), validate=True)
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("Base64 inválido.") from exc


def _xxtea(data: bytes, key: bytes) -> bytes:
    if len(data) < 8 or len(data) % 4:
        raise DecodeError("Bloque XXTEA inválido.")
    plain, size = renz.renz_xxtea_decrypt_custom(data, key)
    if size == 0:
        raise DecodeError("No se pudo descifrar XXTEA.")
    return plain


def decrypt_main(text: str) -> str:
    try:
        raw = _base64(text)
        intermediate = unpad(AES.new(MAIN_KEY, AES.MODE_CBC, IV).decrypt(raw), 16)
        shifted = _xxtea(intermediate, MAIN_KEY)
        # This APK adds 2 to each UTF-8 byte BEFORE XXTEA during export.
        return bytes((byte - 2) & 255 for byte in shifted).decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("No se pudo descifrar el contenido tipo 0.") from exc


@lru_cache(maxsize=1)
def _keys():
    return (
        renz.renz_hkdf_sha256(SEED, SALT[:16], 16),
        renz.renz_hkdf_sha256(SEED, SALT, 32),
        hashlib.pbkdf2_hmac("sha256", SEED, SALT, 100_000, 32),
    )


def decrypt_special(text: str) -> str:
    try:
        raw = _base64(text)
        if not raw or len(raw) % 32:
            raise ValueError
        key16, key32, _ = _keys()
        words = [int.from_bytes(key32[i:i+8], "little") for i in range(0, 32, 8)]
        aes = bytearray()
        for offset in range(0, len(raw), 32):
            # Original AC native tweak: block index, then ZERO (not offset*6).
            subkeys = renz.threefish_set_key(256, words, [offset // 32, 0])
            cipher = [int.from_bytes(raw[offset+i:offset+i+8], "little") for i in range(0, 32, 8)]
            out = [0] * 4
            renz.threefish_decrypt256_block(subkeys, cipher, out)
            aes.extend(b"".join(word.to_bytes(8, "little") for word in out))
        # Only 0 or 16 zero bytes can fill an aligned AES block to 32 bytes.
        # Do not strip genuine zero bytes from the AES ciphertext.
        candidates = [bytes(aes)]
        if len(aes) > 16 and aes.endswith(bytes(16)):
            candidates.append(bytes(aes[:-16]))
        valid = []
        for candidate in candidates:
            try:
                valid.append(unpad(AES.new(key16, AES.MODE_CBC, IV).decrypt(candidate), 16).decode("utf-8"))
            except (ValueError, UnicodeError):
                continue
        if len(valid) != 1:
            raise ValueError
        return valid[0]
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("No se pudo descifrar el contenido tipo 1.") from exc


def decrypt_sensitive(text: str) -> str:
    try:
        # AC uses standard Base64 here, not the invisible alphabet of other apps.
        key = _keys()[2]
        aes = _xxtea(_base64(text), key)
        if len(aes) < 32 or len(aes) % 16:
            raise ValueError
        return unpad(AES.new(key, AES.MODE_CBC, aes[:16]).decrypt(aes[16:]), 16).decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("No se pudo descifrar el contenido tipo 2.") from exc


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DecodeError("JSON con claves duplicadas.")
        result[key] = value
    return result


def _reject_constant(_value):
    raise DecodeError("JSON con números no finitos.")


def _validate_tree(value, depth=0):
    if depth > MAX_DEPTH:
        raise DecodeError("El JSON supera la profundidad permitida.")
    if isinstance(value, dict):
        for key, item in value.items():
            key.encode("utf-8")
            _validate_tree(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _validate_tree(item, depth + 1)
    elif isinstance(value, float) and not math.isfinite(value):
        raise DecodeError("Número fuera del rango JSON.")
    elif isinstance(value, str):
        value.encode("utf-8")


def _fields(obj, main, special, sensitive=()):
    result = dict(obj)
    for keys, method in ((main, decrypt_main), (special, decrypt_special), (sensitive, decrypt_sensitive)):
        for key in keys:
            if key not in obj or obj[key] is None:
                continue
            value = obj[key]
            if not isinstance(value, str):
                raise DecodeError("Un campo cifrado no contiene texto.")
            result[key] = method(value) if value else ""
    return result


def _record(obj):
    result = _fields(obj, MAIN_FIELDS, SPECIAL_FIELDS, SENSITIVE_FIELDS)
    for child, (main, special) in CHILD_FIELDS.items():
        if child in obj:
            if not isinstance(obj[child], dict):
                raise DecodeError("Estructura de perfil inválida.")
            result[child] = _fields(obj[child], main, special)
    return result


def _input(data: bytes) -> str:
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError("Entrada vacía o superior a 8 MiB.")
    return data.decode("utf-8-sig").strip()


def envelope(data: bytes, *, profile: bool) -> dict:
    try:
        text = _input(data)
        if profile:
            if not text.startswith(PROFILE_PREFIX):
                raise DecodeError("El perfil debe comenzar por actunnelvpn://.")
            text = text[len(PROFILE_PREFIX):]
        elif "://" in text:
            raise DecodeError("Se esperaba un catálogo cifrado, no un enlace.")
        obj = json.loads(decrypt_main(text), object_pairs_hook=_unique, parse_constant=_reject_constant)
        if not isinstance(obj, dict) or not obj:
            raise DecodeError("El documento debe ser un objeto JSON no vacío.")
        _validate_tree(obj)
        if profile:
            if "Name" not in obj or "Servers" in obj or "Networks" in obj:
                raise DecodeError("El documento no es un perfil exportado.")
            result = _record(obj)
        else:
            if (not isinstance(obj.get("Version"), str) or not obj["Version"] or
                    any(not isinstance(obj.get(k), list) for k in ("Servers", "Networks")) or
                    not (obj["Servers"] or obj["Networks"]) or
                    any(not isinstance(item, dict) or "Name" not in item
                        for k in ("Servers", "Networks") for item in obj[k])):
                raise DecodeError("Estructura de catálogo inválida.")
            result = _fields(obj, (), (), SENSITIVE_FIELDS)
            for key in ("Servers", "Networks"):
                result[key] = [_record(item) for item in obj[key]]
        _validate_tree(result)
        return result
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("Formato o contenido cifrado inválido.") from exc


def render(value) -> str:
    text = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise DecodeError("La salida supera 8 MiB.")
    return text


def cloud_reference(data: bytes) -> dict:
    """Decode an acvpn:// pointer offline; no embedded account/token or fetch."""
    try:
        text = _input(data)
        if not text.startswith(REFERENCE_PREFIX):
            raise DecodeError("La referencia debe comenzar por acvpn://.")
        reference = decrypt_main(text[len(REFERENCE_PREFIX):])
        if not reference:
            raise DecodeError("Referencia Cloud vacía.")
        return {"kind": "cloud_reference", "reference": reference, "profileDownloaded": False}
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("Referencia Cloud inválida.") from exc
