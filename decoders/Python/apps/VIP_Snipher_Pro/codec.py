"""VIP Snipher Pro 2.9 (29): complete offline RENZ catalogs.

Known fields only; preserve unknown data, types, lists and empty values.
CBC/XXTEA/Threefish validate structure and padding, not authenticity.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
from pathlib import Path
import struct
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

if __package__ and __package__.startswith('decoders.'):
    from ... import renz
    from ..HTTP_FenixVPN import codec as shared
else:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    import renz
    from apps.HTTP_FenixVPN import codec as shared

DecodeError = shared.DecodeError
MAX_BYTES = shared.MAX_BYTES
render = shared.render
SEED = bytes.fromhex('1fea453c1c20a9366214bf96b64a26f1b76e32660d02ab66a1ddc878936186b1')
SALT = bytes.fromhex('c9c5fd1cace2fe51e213935313b2f03ba055190f23b4aced90c36cf3cb43d291')
IV = bytes.fromhex('82aa46e488644f9f3af6b61b69d214cd')
KEY16 = hashlib.sha256(SEED).digest()[:16]

def _hkdf(salt, size):
    prk = hmac.new(salt, SEED, hashlib.sha256).digest()
    return hmac.new(prk, b'\x01', hashlib.sha256).digest()[:size]

HKDF16 = _hkdf(SALT[:16], 16)
HKDF32 = _hkdf(SALT, 32)
PBKDF32 = hashlib.pbkdf2_hmac('sha256', SEED, SALT, 100000, 32)
SERVER_FIELDS = {0: ('Name', 'Subname', 'OpenVPNTCPPort', 'OpenVPNSSLPort', 'UDPSSLPort',
                     'CloudfrontDNS', 'flag', 'Obfs', 'CustomCert'),
                 1: ('ServerIPHost',), 2: ('Username', 'Password')}
NETWORK_FIELDS = {0: ('Name', 'Info', 'DNSResolver', 'TLSVersion'), 1: ('SNIHost', 'Payload')}
NESTED_FIELDS = {
    ('Servers', 'SlowDNS'): {0: ('NSNameServer', 'PubKey')},
    ('Servers', 'V2Ray'): {0: ('UUID',), 1: ('PATH', 'V2RayHost')},
    ('Networks', 'ProxySettings'): {0: ('Squid', 'Port')},
    ('Networks', 'V2Ray'): {1: ('SNIHost', 'CustomV2RAYConfig')},
}

def _b64(text):
    if not isinstance(text, str) or not text or len(text.encode('utf-8')) > MAX_BYTES:
        raise DecodeError('Campo VIP Snipher inválido.')
    return base64.b64decode(''.join(text.split()), validate=True)

def _xxtea(raw, key):
    if len(raw) < 8 or len(raw) % 4:
        raise DecodeError('Longitud XXTEA inválida.')
    result, size = renz.renz_xxtea_decrypt_custom(raw, key)
    if not size:
        raise DecodeError('Contenido XXTEA inválido.')
    return result

def decode_main(text):
    raw = _b64(text)
    if not raw or len(raw) % 16:
        raise DecodeError('Sobre VIP Snipher inválido.')
    raw = unpad(AES.new(KEY16, AES.MODE_CBC, IV).decrypt(raw), 16)
    return bytes((v - 2) & 255 for v in _xxtea(raw, KEY16)).decode('utf-8')

def decode_special(text):
    raw = _b64(text)
    if not raw or len(raw) % 32:
        raise DecodeError('Bloques Threefish inválidos.')
    schedule = renz.threefish_set_key(256, list(struct.unpack('<4Q', HKDF32)), [0, 0])
    clear = bytearray()
    for offset in range(0, len(raw), 32):
        words = [0, 0, 0, 0]
        renz.threefish_decrypt256_block(schedule, list(struct.unpack('<4Q', raw[offset:offset + 32])), words)
        clear.extend(struct.pack('<4Q', *words))
    # Zero fill is outside AES. Retain legitimate ciphertext zeros up to its
    # next block boundary, then require valid PKCS7 and UTF-8.
    size = ((len(bytes(clear).rstrip(b'\0')) + 15) // 16) * 16
    if not size:
        raise DecodeError('Contenido Threefish vacío.')
    return unpad(AES.new(HKDF16, AES.MODE_CBC, IV).decrypt(bytes(clear[:size])), 16).decode('utf-8')

def decode_sensitive(text):
    raw = _xxtea(_b64(text), PBKDF32)
    if len(raw) < 32 or len(raw) % 16:
        raise DecodeError('Sobre de credenciales inválido.')
    return unpad(AES.new(PBKDF32, AES.MODE_CBC, raw[:16]).decrypt(raw[16:]), 16).decode('utf-8')

def open_outer(data):
    return json.loads(decode_main(shared._bounded(data).decode('utf-8-sig').strip()),
                      object_pairs_hook=shared._unique, parse_constant=shared._constant)

def decode_catalog(data: bytes) -> dict:
    try:
        doc = open_outer(data)
        shared._validate(doc)
        if (not isinstance(doc, dict) or not isinstance(doc.get('Version'), str) or not doc['Version'] or
                any(not isinstance(doc.get(k), list) or not doc[k] for k in ('Servers', 'Networks'))):
            raise DecodeError('Estructura de catálogo VIP Snipher incompatible.')
        cache = {}
        def fields(record, schema):
            if not isinstance(record, dict):
                raise DecodeError('Registro de catálogo inválido.')
            for mode, names in schema.items():
                for name in names:
                    if name not in record or record[name] is None or record[name] == '':
                        continue
                    value = record[name]
                    if not isinstance(value, str):
                        raise DecodeError('Campo cifrado sin texto.')
                    identity = mode, value
                    if identity not in cache:
                        cache[identity] = (decode_main, decode_special, decode_sensitive)[mode](value)
                    record[name] = cache[identity]
        fields(doc, {2: ('Username', 'Password')})
        for section, schema in (('Servers', SERVER_FIELDS), ('Networks', NETWORK_FIELDS)):
            for item in doc[section]:
                if not isinstance(item, dict) or not isinstance(item.get('Name'), str):
                    raise DecodeError('Perfil sin nombre.')
                fields(item, schema)
                for (parent, key), nested in NESTED_FIELDS.items():
                    if parent == section and item.get(key) is not None:
                        fields(item[key], nested)
        shared._validate(doc)
        render(doc)
        return doc
    except (ValueError, UnicodeError, TypeError, KeyError, RecursionError, OverflowError) as exc:
        raise DecodeError('Catálogo inválido o incompatible con VIP Snipher Pro 2.9.') from exc
