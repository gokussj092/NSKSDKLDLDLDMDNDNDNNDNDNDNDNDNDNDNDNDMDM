"""Halcon R Net 4.1.4/1391: symbol/Base64 AES256-GCM catalog, no network."""
from __future__ import annotations
import base64
import hashlib
import json
import os
import re
from Crypto.Cipher import AES

MAX_BYTES = 8 * 1024 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
ALPHABET = '▙▚▛▜▝▞▟▃▄▅▆▇█▉▊▐'
PASSWORD_ENV = 'SPDECODE_HALCON_CATALOG_PASSWORD'
TEXT_FIELDS = frozenset(('serverName', 'serverHost', 'serverPort', 'serverFlag',
    'serverInfo', 'proxyHost', 'proxyPort', 'payload', 'sni', 'vipApiUrl',
    'methodCountry', 'mode', 'username', 'password'))

class DecodeError(ValueError):
    pass

def catalog_password() -> str:
    value = os.environ.get(PASSWORD_ENV, '')
    if not re.fullmatch(r'[!-~]{65}[0-9A-F]{64}', value):
        raise DecodeError('Clave del catálogo Halcon no configurada.')
    return value

def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise DecodeError('JSON Halcon con claves duplicadas.')
        result[key] = value
    return result

def _constant(value):
    raise DecodeError('Valor JSON Halcon no válido.')

def _validate(obj):
    stack = [(obj, 0)]
    count = 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if depth > 64 or count > 250000:
            raise DecodeError('Catálogo Halcon superior al límite estructural.')
        if isinstance(node, dict): stack.extend((v, depth + 1) for v in node.values())
        elif isinstance(node, list): stack.extend((v, depth + 1) for v in node)
    if (not isinstance(obj, dict) or not isinstance(obj.get('version'), str) or not obj['version'] or
        not isinstance(obj.get('releaseNotes'), str) or not isinstance(obj.get('servers'), list) or
        not obj['servers']):
        raise DecodeError('Estructura del catálogo Halcon incompatible.')
    for server in obj['servers']:
        if (not isinstance(server, dict) or any(not isinstance(server.get(k), str) for k in TEXT_FIELDS) or
            not server['serverName'] or type(server.get('tunnelType')) is not int):
            raise DecodeError('Registro del catálogo Halcon incompatible.')

def render(obj) -> str:
    try:
        text = json.dumps(obj, ensure_ascii=False, indent=2, allow_nan=False)
        if len(text.encode()) > MAX_OUTPUT_BYTES:
            raise DecodeError('Resultado Halcon superior al límite.')
        return text
    except (TypeError, ValueError, RecursionError) as exc:
        raise DecodeError('No se pudo representar el catálogo Halcon.') from exc

def decode_catalog(data: bytes) -> dict:
    password = catalog_password()
    try:
        if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_BYTES:
            raise ValueError()
        text = data.decode('utf-8').strip()
        if not text or len(text) % 2 or any(c not in ALPHABET for c in text):
            raise ValueError()
        lookup = {c: i for i, c in enumerate(ALPHABET)}
        b64 = bytes((lookup[text[i]] << 4) | lookup[text[i+1]] for i in range(0, len(text), 2))
        raw = base64.b64decode(b64, validate=True)
        if len(raw) < 28: raise ValueError()
        key = hashlib.sha256(password.encode()).digest()
        plain = AES.new(key, AES.MODE_GCM, nonce=raw[:12]).decrypt_and_verify(raw[12:-16], raw[-16:])
        obj = json.loads(plain.decode(), object_pairs_hook=_unique, parse_constant=_constant)
        _validate(obj)
        render(obj)
        return obj
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise DecodeError('Catálogo Halcon inválido o no compatible con 4.1.4.') from exc
