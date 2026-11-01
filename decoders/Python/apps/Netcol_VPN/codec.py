"""Netcol VPN 14.2 (142): block-symbol AES-CBC envelope and Blowfish fields."""
from __future__ import annotations
import base64
import hashlib
import json
from pathlib import Path
import sys
from Crypto.Cipher import AES, Blowfish
from Crypto.Util.Padding import unpad

if __package__ and '.' in __package__:
    from ..HTTP_FenixVPN import codec as shared
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from HTTP_FenixVPN import codec as shared

DecodeError = shared.DecodeError
MAX_BYTES = shared.MAX_BYTES
render = shared.render
ALPHABET = '▙▚▛▜▝▞▟▃▄▅▆▇█▉▊▐'
CATALOG_PASSWORD = b'FamiliaGelves24'
CATALOG_KEY = hashlib.sha256(CATALOG_PASSWORD.hex().upper().encode('ascii')).digest()
FIELD_KEY = b'UniversalPro24'
USER_KEY = b'LiamSebas18'
FIELD_IV = b'abcdefgh'
SERVER_FIELDS = frozenset(('ServerIP', 'ProxyIP', 'Payload', 'SNI', 'Slowchave', 'Nameserver', 'ServerUser'))

def decrypt_catalog(data: bytes) -> str:
    try:
        text = shared._bounded(data).decode('utf-8-sig').strip()
        if not text or len(text) % 2 or any(c not in ALPHABET for c in text):
            raise ValueError()
        raw = bytes(ALPHABET.index(text[i]) * 16 + ALPHABET.index(text[i + 1])
                    for i in range(0, len(text), 2))
        ciphertext = base64.b64decode(raw, validate=True)
        if not ciphertext or len(ciphertext) % 16:
            raise ValueError()
        return unpad(AES.new(CATALOG_KEY, AES.MODE_CBC, bytes(16)).decrypt(ciphertext), 16).decode('utf-8')
    except (ValueError, UnicodeError) as exc:
        raise DecodeError('Sobre Netcol inválido o no compatible.') from exc

def decrypt_field(value: str, *, username=False) -> str:
    if value == '':
        return value
    try:
        if not isinstance(value, str) or len(value.encode('utf-8')) > MAX_BYTES:
            raise ValueError()
        raw = base64.b64decode(''.join(value.split()).encode('ascii'), validate=True)
        if not raw or len(raw) % 8:
            raise ValueError()
        cipher = Blowfish.new(USER_KEY if username else FIELD_KEY, Blowfish.MODE_CBC, FIELD_IV)
        return unpad(cipher.decrypt(raw), 8).decode('utf-8')
    except (ValueError, UnicodeError) as exc:
        raise DecodeError('Campo Netcol inválido o no compatible.') from exc

def decode_catalog(data: bytes) -> dict:
    try:
        obj = json.loads(decrypt_catalog(data), object_pairs_hook=shared._unique,
                         parse_constant=shared._constant)
        shared._validate(obj)
        if (not isinstance(obj, dict) or not isinstance(obj.get('Version'), str) or
                not obj['Version'] or not isinstance(obj.get('Servers'), list) or not obj['Servers']):
            raise DecodeError('Estructura Netcol incompatible.')
        result = obj.copy()
        result['Servers'] = []
        for item in obj['Servers']:
            if not isinstance(item, dict) or not isinstance(item.get('Name'), str):
                raise DecodeError('Perfil Netcol incompatible.')
            entry = item.copy()
            for name in SERVER_FIELDS & item.keys():
                if not isinstance(item[name], str):
                    raise DecodeError('Un campo Netcol no contiene texto.')
                entry[name] = decrypt_field(item[name], username=name == 'ServerUser')
            result['Servers'].append(entry)
        shared._validate(result)
        render(result)
        return result
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise DecodeError('Catálogo Netcol inválido o incompatible con 14.2.') from exc
