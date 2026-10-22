"""UT Loop Pro VPN 22.10.26: signed OTA, cached catalogs and SSH banners."""
from __future__ import annotations
import base64
import hashlib
import json
import re
import struct
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

MAX_BYTES = 8 * 1024 * 1024
OTA_SCHEME = b'uch3-pr0-0ta-scheme-v2'
OTA_MASK = bytes.fromhex('8f83b75712866b951ff4f2f87f3d9474ea43f8011e45148fca96ec15fd39c965')
SIGNATURE_PUBLIC_KEY = base64.b64decode('MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjyGJEwSrdUacirh+kV+1bYzPvlSKGEeeTwF362vx7Vz1S9jdMGqrUIBFnH9y+tfm3oX0GME23rvt4tA7bscFWGrl8ocqpccw957xxY718bYWmQSboIBGt+W0qAsJkz5YF2mk9ns20P7Zz28CAeXfSonzDHpivbK69m2ftvbHYMSdZo+WSxJoBDyoXNaYvXyY+lFYWtN2/t1WFL23yy3qYbr+QmKPEouYtkOjJKZekmjGu9x/dMhfMHY0FgbOdtgmp/tMEyv8hrSjd4d9KXxYsS6Lt3SiaBvWwTh2ffphZOUoYTQlTHeZ1lh4pdqupFZFMXnvAbF3qNAlO8+tptSf2wIDAQAB')
BANNER_CERT_SHA256 = (
    'FC692B18C1E532FDA8B4CF485AA26355C006B3DC4442BF228684209CDB58A1D6',
    '4102A213C55BC96C97B3451679831D392AB7BABD6A60B4AB2B6A5897A69EE83F',
)
BANNER_MASKS = (
    'AcCXGRWjhbp85ER6z4BFwrXQWUg6uA4eIW7THGweEqa7M2mCGTTY8anVGHA=',
    'h/STJJ0eoQaWIV4Z9qRnRP6EES7AEyckzt+GmGp1i/QlGVk24DlOJLmKmp8=',
)


class DecodeError(ValueError):
    pass


def _bounded(data: bytes) -> bytes:
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError('Entrada vacía o superior a 8 MiB.')
    return data


def _base64(value: str) -> bytes:
    if not isinstance(value, str) or len(value) > MAX_BYTES:
        raise DecodeError('Base64 inválido.')
    return base64.b64decode(''.join(value.split()), validate=True)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DecodeError('JSON ambiguo.')
        result[key] = value
    return result


def _invalid_constant(value):
    raise DecodeError('Constante JSON inválida.')


def _json(data):
    return json.loads(data, object_pairs_hook=_unique, parse_constant=_invalid_constant)


def _gcm(raw: bytes, key: bytes, aad=b'') -> bytes:
    if len(raw) < 28:
        raise DecodeError('Sobre GCM incompleto.')
    cipher = AES.new(key, AES.MODE_GCM, nonce=raw[:12], mac_len=16)
    cipher.update(aad)
    return cipher.decrypt_and_verify(raw[12:-16], raw[-16:])


def decode_catalog(data: bytes, *, require_signature=False) -> dict:
    """Open a signed remote envelope or an explicitly offline Base64 cache copy.

    All original sections, records, types and metadata are returned unchanged.
    A signed input never falls back to the unsigned cache format on failure.
    """
    try:
        text = _bounded(data).decode('utf-8-sig').strip()
        if text.startswith('{'):
            envelope = _json(text)
            if not isinstance(envelope, dict) or not {'data', 'sig'} <= envelope.keys():
                raise DecodeError('Falta el sobre firmado.')
            encoded = envelope['data']
            if not isinstance(encoded, str):
                raise DecodeError('Datos firmados inválidos.')
            key = RSA.import_key(SIGNATURE_PUBLIC_KEY)
            pkcs1_15.new(key).verify(SHA256.new(encoded.encode('utf-8')), _base64(envelope['sig']))
        elif require_signature:
            raise DecodeError('La descarga requiere firma RSA.')
        else:
            encoded = text
        digest = hashlib.sha256(OTA_SCHEME).digest()
        ota_key = bytes(a ^ b for a, b in zip(OTA_MASK, digest))
        doc = _json(_gcm(_base64(encoded), ota_key).decode('utf-8'))
        if not isinstance(doc, dict) or not any(k in doc for k in ('Servers', 'Tweaks')):
            raise DecodeError('Documento de catálogo inválido.')
        for name in ('Servers', 'Tweaks'):
            if name in doc and (not isinstance(doc[name], list) or any(not isinstance(v, dict) for v in doc[name])):
                raise DecodeError('Sección de catálogo inválida.')
        return doc
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        raise DecodeError('Catálogo inválido o incompatible con UT Loop Pro VPN 22.10.26.') from None


def _xxtea(raw: bytes, key=b'uchehacks') -> bytes:
    """APK util.d: little-endian XXTEA, custom delta -1704280, length word."""
    if len(raw) < 8 or len(raw) % 4:
        raise DecodeError('Sobre XXTEA inválido.')
    values = list(struct.unpack('<' + 'I' * (len(raw) // 4), raw))
    keys = struct.unpack('<4I', key[:16].ljust(16, b'\0'))
    mask = 0xffffffff
    total = ((6 + 52 // len(values)) * -1704280) & mask
    y = values[0]
    def mx(z, y, p, e):
        return (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((total ^ y) + (keys[(p & 3) ^ e] ^ z))) & mask
    for _ in range(6 + 52 // len(values)):
        e = total >> 2 & 3
        for p in range(len(values) - 1, 0, -1):
            y = values[p] = (values[p] - mx(values[p - 1], y, p, e)) & mask
        y = values[0] = (values[0] - mx(values[-1], y, 0, e)) & mask
        total = (total + 1704280) & mask
    size = values[-1]
    if not len(raw) - 7 <= size <= len(raw) - 4:
        raise DecodeError('Longitud XXTEA inválida.')
    return struct.pack('<' + 'I' * len(values), *values)[:size]


def decode_banner(data: bytes) -> str:
    """Optional SSH greeting helper; this is not a VPN file/catalog format."""
    try:
        text = _bounded(data).decode('utf-8')
        match = re.search(r'title\s*=\s*"([A-Za-z0-9+/=]+)"', text)
        if match:
            raw = _base64(match[1])
            for digest_hex, masked in zip(BANNER_CERT_SHA256, BANNER_MASKS):
                digest = bytes.fromhex(digest_hex)
                encoded = _base64(masked)
                stream = b''.join(hashlib.sha256(digest + bytes([i])).digest() for i in range((len(encoded) + 31) // 32))
                key = _base64(bytes(a ^ b for a, b in zip(encoded, stream)).decode('utf-8'))
                try:
                    return _gcm(raw, key, b'utloop-banner-v1').decode('utf-8')
                except ValueError:
                    continue
            # The APK uses the same quoted carrier for older XXTEA banners.
            # Only this legacy SSH helper falls back; signed OTA never does.
        parts = text.split('"')
        if len(parts) < 3:
            raise DecodeError('Banner incompatible.')
        return _xxtea(_base64(parts[1])).decode('utf-8')
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise DecodeError('Banner inválido o incompatible con UT Loop Pro VPN.') from None


def render(doc) -> str:
    return json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + '\n'
