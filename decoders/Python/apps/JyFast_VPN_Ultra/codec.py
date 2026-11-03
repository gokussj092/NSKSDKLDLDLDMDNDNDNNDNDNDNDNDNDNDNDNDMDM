"""JyFast VPN Ultra 9: exact Rt symbol alphabet, SHA-256/AES-CBC catalogs."""
from __future__ import annotations
import base64
import hashlib
import json
from pathlib import Path
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

if __package__ and '.' in __package__:
    from ..HTTP_FenixVPN import codec as shared
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from HTTP_FenixVPN import codec as shared

DecodeError = shared.DecodeError
MAX_BYTES = shared.MAX_BYTES
MAX_FILE_BYTES = shared.MAX_FILE_BYTES
render = shared.render
# Rt.a accepts indices 0..64 only; the last six characters are NOT valid input.
ALPHABET = '!?-=∆×÷ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
PASSWORDS = {'free': 'JyFastv1c2', 'premium': 'Jyfastv1c'}
FIELD_PASSWORD = 'Key: =Kenova_code'
SERVER_FIELDS = frozenset((
    'ServerIP', 'ProxyIP', 'ServerUser', 'ServerPass', 'Payload', 'SNI',
    'Slowchave', 'Nameserver', 'Slowdns', 'udpserver', 'udpauth', 'udpobfs',
    'udpbuffer', 'udpdown', 'udpup', 'v2rayJson', 'pubkeydnstt', 'nsdnstt',
    'dnsdnstt', 'fastdnsip', 'bhttpdown', 'bhttpup',
))
BUNDLE_KIND = 'spdecode-jyfast-vpn-ultra-catalogs-v1'


def decrypt(value: str, password: str) -> str:
    if not isinstance(value, str) or not value or len(value.encode('utf-8')) > MAX_BYTES:
        raise DecodeError('Campo JyFast vacío o superior al límite.')
    try:
        mapped = ''.join(BASE64_ALPHABET[ALPHABET.index(c)] for c in value)
        if len(mapped) % 4 == 1:
            raise ValueError('base64 length')
        ciphertext = base64.b64decode(mapped + '=' * (-len(mapped) % 4), validate=True)
        if not ciphertext or len(ciphertext) % 16:
            raise ValueError('AES length')
        key = hashlib.sha256(password.encode('utf-8')).digest()
        return unpad(AES.new(key, AES.MODE_CBC, bytes(16)).decrypt(ciphertext), 16).decode('utf-8')
    except (ValueError, UnicodeError, IndexError) as exc:
        raise DecodeError('Sobre JyFast inválido o no compatible.') from exc


def decode_catalog(data: bytes, *, mode: str = 'free') -> dict:
    if mode not in PASSWORDS:
        raise DecodeError('Modo JyFast no compatible.')
    try:
        text = shared._bounded(data).decode('utf-8-sig').strip()
        obj = json.loads(decrypt(text, PASSWORDS[mode]), object_pairs_hook=shared._unique,
                         parse_constant=shared._constant)
        shared._validate(obj)
        if (not isinstance(obj, dict) or not isinstance(obj.get('Version'), str)
                or not obj['Version'] or not isinstance(obj.get('Servers'), list)
                or not obj['Servers']):
            raise DecodeError('Estructura JyFast incompatible.')
        result = obj.copy()
        result['Servers'] = []
        for item in obj['Servers']:
            if not isinstance(item, dict) or not isinstance(item.get('Name'), str):
                raise DecodeError('Perfil JyFast inválido.')
            entry = item.copy()
            for name in SERVER_FIELDS & item.keys():
                value = item[name]
                if not isinstance(value, str):
                    raise DecodeError('Un campo cifrado JyFast no contiene texto.')
                entry[name] = decrypt(value, FIELD_PASSWORD) if value else ''
            result['Servers'].append(entry)
        shared._validate(result)
        return result
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise DecodeError('Catálogo JyFast inválido o no compatible con la versión 9.') from exc


def decode_bundle(data: bytes) -> dict:
    try:
        obj = json.loads(shared._bounded(data).decode('utf-8'),
                         object_pairs_hook=shared._unique, parse_constant=shared._constant)
        if (not isinstance(obj, dict) or set(obj) != {'kind', 'catalogs'}
                or obj['kind'] != BUNDLE_KIND or not isinstance(obj['catalogs'], dict)
                or set(obj['catalogs']) != set(PASSWORDS)):
            raise DecodeError('Lote JyFast incompleto o incompatible.')
        catalogs = {}
        for mode in PASSWORDS:
            value = obj['catalogs'][mode]
            if not isinstance(value, str):
                raise DecodeError('Fuente JyFast inválida.')
            raw = base64.b64decode(value.encode('ascii'), validate=True)
            catalogs[mode] = decode_catalog(raw, mode=mode)
        result = {'provider': 'jyfast-vpn-ultra', 'complete': True, 'catalogs': catalogs}
        shared._validate(result)
        render(result)  # Enforce the same complete-output quota for direct callers.
        return result
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise DecodeError('Lote JyFast inválido o incompleto.') from exc


def decode_profile(data: bytes) -> dict:
    """r6.b importer: the existing, byte-identical GCM/DES SKS engine."""
    return shared.decode_profile(data)
