"""My Tunnel Proxy 2.3 wire formats; offline, strict, no APK at runtime."""
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

# Reuse the historical primitives, without changing their keys or dispatchers.
ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from decoders.Python import renz

MAX_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 64
SEED = bytes.fromhex("ecd4f3ceaf62556b0f4f9c43207511249c4bdc59b68ac9ab9d7b490428e88fde")
SALT = bytes.fromhex("be432e5a50952a899b29b7c23162fe70defca1061c9fa7927c65c3f6ebe9f77e")
IV = bytes.fromhex("b329f9d1ab699b9ad1aa9c4ce918d4f8")
MAIN_KEY = hashlib.sha256(SEED).digest()[:16]
MAIN_FIELDS = frozenset({
    "Name", "Subname", "Info", "flag", "OpenVPNTCPPort", "OpenVPNSSLPort",
    "UDPSSLPort", "CloudfrontDNS", "Obfs", "CustomCert", "NSNameServer",
    "PubKey", "UpMbps", "DlMbps", "RecvConnectionWindow", "UUID",
    "CustomV2RAYPayload", "CustomV2RAYProxy", "DNSResolver", "Squid", "Port",
    "TLSVersion",
})
SPECIAL_FIELDS = frozenset({
    "ServerIPHost", "SNIHost", "Payload", "PATH", "V2RayHost", "CustomV2RAYConfig",
})
SENSITIVE_FIELDS = frozenset({"Username", "Password"})


class DecodeError(ValueError):
    """Sanitized error: never include provider data or credential values."""


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
        return _xxtea(intermediate, MAIN_KEY).decode("utf-8")
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
            # libovpn3.so: t0 = byte_offset / 32; t1 = byte_offset * 6.
            subkeys = renz.threefish_set_key(256, words, [offset // 32, offset * 6])
            cipher = [int.from_bytes(raw[offset+i:offset+i+8], "little") for i in range(0, 32, 8)]
            out = [0] * 4
            renz.threefish_decrypt256_block(subkeys, cipher, out)
            aes.extend(b"".join(word.to_bytes(8, "little") for word in out))
        # AES ciphertext is block-aligned: its Threefish padding is 0 or 16
        # bytes. Native rstrip(0) also eats legitimate ciphertext zero bytes.
        # Validate both possible lengths with PKCS#7; never trim ciphertext.
        aes = bytes(aes)
        candidates = [aes]
        if len(aes) > 16 and aes.endswith(b"\0" * 16):
            candidates.append(aes[:-16])
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
        if any(c not in "\u200b\u200c\u200d" for c in text):
            raise ValueError
        bits = [int(c == "\u200c") for c in text if c != "\u200d"]
        if not bits or len(bits) % 8:
            raise ValueError
        encoded = bytearray()
        for offset in range(0, len(bits), 8):
            value = 0
            for bit in bits[offset:offset+8]:
                value = (value << 1) | bit
            encoded.append((((value << 1) & 0xaa) | ((value >> 1) & 0x55)) ^ 0x5a)
        key = _keys()[2]
        aes = _xxtea(bytes(encoded), key)
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


def envelope(data: bytes, *, profile: bool) -> dict:
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError("Entrada vacía o superior a 8 MiB.")
    try:
        text = data.decode("utf-8-sig").strip()
        if profile:
            if not text.startswith("mytunnelproxy://"):
                raise DecodeError("El perfil debe comenzar por mytunnelproxy://.")
            text = text[len("mytunnelproxy://"):]
        elif "://" in text:
            raise DecodeError("Se esperaba un catálogo cifrado, no un enlace.")
        obj = json.loads(decrypt_main(text), object_pairs_hook=_unique, parse_constant=_reject_constant)
        if not isinstance(obj, dict) or not obj:
            raise DecodeError("El documento debe ser un objeto JSON no vacío.")
        if profile:
            if "Name" not in obj or "Servers" in obj or "Networks" in obj:
                raise DecodeError("El documento no es un perfil exportado.")
        elif (not isinstance(obj.get("Version"), str) or not obj["Version"] or
              any(not isinstance(obj.get(k), list) for k in ("Servers", "Networks")) or
              not (obj["Servers"] or obj["Networks"]) or
              any(not isinstance(item, dict) or "Name" not in item
                  for k in ("Servers", "Networks") for item in obj[k])):
            raise DecodeError("Estructura de catálogo inválida.")
        return _walk(obj)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("Formato o contenido cifrado inválido.") from exc


def _walk(value, depth=0):
    if depth > MAX_DEPTH:
        raise DecodeError("El JSON supera la profundidad permitida.")
    if isinstance(value, list):
        return [_walk(v, depth + 1) for v in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            method = (decrypt_main if key in MAIN_FIELDS else
                      decrypt_special if key in SPECIAL_FIELDS else
                      decrypt_sensitive if key in SENSITIVE_FIELDS else None)
            if method and item is not None:
                if not isinstance(item, str):
                    raise DecodeError("Un campo cifrado no contiene texto.")
                result[key] = method(item) if item else ""
            else:
                result[key] = _walk(item, depth + 1)
        return result
    if isinstance(value, float) and not math.isfinite(value):
        raise DecodeError("Número fuera del rango JSON.")
    if isinstance(value, str):
        value.encode("utf-8")
    return value


def render(value) -> str:
    text = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise DecodeError("La salida supera 8 MiB.")
    return text


def cloud_reference(data: bytes) -> dict:
    """Decode the pointer only; it is not a VPN profile and triggers no fetch."""
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError("Referencia vacía o superior a 8 MiB.")
    try:
        text = data.decode("utf-8-sig").strip()
        if not text.startswith("mytunnel://"):
            raise DecodeError("La referencia debe comenzar por mytunnel://.")
        reference = decrypt_main(text[len("mytunnel://"):])
        if not reference:
            raise DecodeError("Referencia Cloud vacía.")
        return {"kind": "cloud_reference", "reference": reference, "profileDownloaded": False}
    except UnicodeError as exc:
        raise DecodeError("Referencia UTF-8 inválida.") from exc
