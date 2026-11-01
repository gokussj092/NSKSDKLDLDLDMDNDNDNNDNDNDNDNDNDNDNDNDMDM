"""Strict IZPH VPN PRO 6.0 catalog reader; reuse the historical IZPH primitives."""
from __future__ import annotations
import base64
import json
from pathlib import Path
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

if __package__ and __package__.startswith('decoders.'):
    from ... import izph
    from ..HTTP_FenixVPN import codec as shared
else:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    import izph
    from apps.HTTP_FenixVPN import codec as shared

DecodeError = shared.DecodeError
MAX_BYTES = shared.MAX_BYTES
render = shared.render
KEY16 = izph.IZPH_SHA256_KEY_16
HKDF16 = izph.izph_get_hkdf_key_16()
HKDF32 = izph.izph_get_hkdf_key()
PBKDF32 = izph.izph_get_pbkdf2_key()
IV = izph.IZPH_FIXED_IV
SERVER_FIELDS = {0: ('Name', 'Subname', 'OpenVPNTCPPort', 'OpenVPNSSLPort',
                     'CloudfrontDNS', 'flag', 'Obfs', 'CustomCert'),
                 1: ('ServerIPHost',), 2: ('Username', 'Password')}
NETWORK_FIELDS = {0: ('Name', 'Info', 'DNSResolver', 'TLSVersion', 'SSCommand'),
                  1: ('SNIHost', 'Payload')}
NESTED_FIELDS = {
    ('Servers', 'SlowDNS'): {0: ('NSNameServer', 'PubKey')},
    ('Servers', 'V2Ray'): {0: ('UUID',), 1: ('PATH', 'V2RayHost')},
    ('Networks', 'ProxySettings'): {0: ('Squid', 'Port')},
    ('Networks', 'V2Ray'): {1: ('SNIHost', 'CustomV2RAYConfig')},
}

def _b64(text):
    if not isinstance(text, str) or not text or len(text.encode('utf-8')) > MAX_BYTES:
        raise DecodeError('Campo IZPH inválido.')
    return base64.b64decode(''.join(text.split()), validate=True)

def decode_main(text):
    raw = _b64(text)
    if not raw or len(raw) % 16:
        raise DecodeError('Sobre IZPH inválido.')
    return izph.izph_decrypt_type0(raw).decode('utf-8')

def decode_special(text):
    raw = _b64(text)
    if not raw or len(raw) % 32:
        raise DecodeError('Bloques IZPH Threefish inválidos.')
    # Original build60 increments the tweak: (blockIndex, blockIndex * 64).
    clear = izph.izph_threefish256_decrypt(raw, HKDF32)
    # Keep legitimate trailing AES ciphertext zeros up to a block boundary.
    size = ((len(clear.rstrip(bytes(1))) + 15) // 16) * 16
    if not size:
        raise DecodeError('Contenido IZPH Threefish vacío.')
    return unpad(AES.new(HKDF16, AES.MODE_CBC, IV).decrypt(clear[:size]), 16).decode('utf-8')

def decode_sensitive(text):
    raw = _b64(text)
    if len(raw) < 8 or len(raw) % 4:
        raise DecodeError('Sobre de credenciales IZPH inválido.')
    return izph.izph_decrypt_type2(text.encode('utf-8')).decode('utf-8')

def open_outer(data):
    return json.loads(decode_main(shared._bounded(data).decode('utf-8-sig').strip()),
                      object_pairs_hook=shared._unique, parse_constant=shared._constant)

def decode_catalog(data: bytes) -> dict:
    try:
        doc = open_outer(data)
        shared._validate(doc)
        if (not isinstance(doc, dict) or not isinstance(doc.get('Version'), str) or not doc['Version'] or
                any(not isinstance(doc.get(k), list) or not doc[k] for k in ('Servers', 'Networks'))):
            raise DecodeError('Estructura de catálogo IZPH incompatible.')
        cache = {}
        def fields(record, schema):
            if not isinstance(record, dict):
                raise DecodeError('Registro de catálogo IZPH inválido.')
            for mode, names in schema.items():
                for name in names:
                    if name not in record or record[name] is None or record[name] == '':
                        continue
                    value = record[name]
                    if not isinstance(value, str):
                        raise DecodeError('Campo cifrado IZPH sin texto.')
                    identity = mode, value
                    if identity not in cache:
                        cache[identity] = (decode_main, decode_special, decode_sensitive)[mode](value)
                    record[name] = cache[identity]
        fields(doc, {2: ('Username', 'Password')})
        for section, schema in (('Servers', SERVER_FIELDS), ('Networks', NETWORK_FIELDS)):
            for item in doc[section]:
                if not isinstance(item, dict) or not isinstance(item.get('Name'), str):
                    raise DecodeError('Perfil IZPH sin nombre.')
                fields(item, schema)
                for (parent, key), nested in NESTED_FIELDS.items():
                    if parent == section and item.get(key) is not None:
                        fields(item[key], nested)
        shared._validate(doc)
        render(doc)
        return doc
    except (ValueError, UnicodeError, TypeError, KeyError, RecursionError, OverflowError, izph.IZPHError) as exc:
        raise DecodeError('Catálogo inválido o incompatible con IZPH VPN PRO 6.0.') from exc
