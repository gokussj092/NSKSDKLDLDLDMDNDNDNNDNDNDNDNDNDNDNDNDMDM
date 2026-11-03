"""ALFAISAL Tunnel+ build39 complete CBC catalogs; preserve all three lists."""
from __future__ import annotations
import base64
import hashlib
import json
from pathlib import Path
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
if __package__ and __package__.startswith('decoders.'):
    from ..HTTP_FenixVPN import codec as shared
else:
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
    from apps.HTTP_FenixVPN import codec as shared

DecodeError = shared.DecodeError
MAX_BYTES = shared.MAX_BYTES
render = shared.render
# Format key recovered from gb.o; HTTP credentials are separate backend secrets.
KEY = hashlib.sha256(b'#ALFAISAL VPN (FREE) 2020#').digest()
IV = bytes(16)
SERVER_FIELDS = ('Username','Password','SSHUsername','SSHPassword')
NETWORK_FIELDS = ('Payload','SNIHost')

def decrypt(text):
    if not isinstance(text,str) or not text or len(text.encode())>MAX_BYTES:
        raise DecodeError('Campo ALFAISAL inválido.')
    raw=base64.b64decode(''.join(text.split()),validate=True)
    if not raw or len(raw)%16:
        raise DecodeError('Sobre CBC ALFAISAL inválido.')
    return unpad(AES.new(KEY,AES.MODE_CBC,IV).decrypt(raw),16).decode('utf-8')

def open_outer(data):
    return json.loads(decrypt(shared._bounded(data).decode('utf-8-sig').strip()),
                      object_pairs_hook=shared._unique,parse_constant=shared._constant)

def decrypt_field(text):
    # gb.m$a.b catches GeneralSecurityException and returns the original field.
    # Three legacy proxy values in the live catalog use that confirmed path.
    if not isinstance(text,str) or len(text.encode())>MAX_BYTES:
        raise DecodeError('Campo ALFAISAL inválido.')
    raw=base64.b64decode(''.join(text.split()),validate=True)
    try:
        if not raw or len(raw)%16:raise ValueError('CBC length')
        clear=unpad(AES.new(KEY,AES.MODE_CBC,IV).decrypt(raw),16)
    except ValueError:
        return text
    return clear.decode('utf-8')

def decode_catalog(data: bytes) -> dict:
    try:
        doc=open_outer(data);shared._validate(doc)
        if (not isinstance(doc,dict) or not isinstance(doc.get('Version'),str) or not doc['Version'] or
            any(not isinstance(doc.get(k),list) for k in ('Servers','Networks','SSLNetworks')) or not doc['Servers']):
            raise DecodeError('Estructura ALFAISAL incompatible.')
        cache={}
        def fields(record,names):
            if not isinstance(record,dict):raise DecodeError('Registro ALFAISAL inválido.')
            for name in names:
                if name not in record or record[name] is None or record[name]=='':continue
                value=record[name]
                if not isinstance(value,str):raise DecodeError('Campo ALFAISAL sin texto.')
                if value not in cache:cache[value]=decrypt_field(value)
                record[name]=cache[value]
        fields(doc,('Username','Password'))
        for section in ('Servers','Networks','SSLNetworks'):
            for record in doc[section]:
                if not isinstance(record,dict) or not isinstance(record.get('Name'),str):
                    raise DecodeError('Perfil ALFAISAL sin nombre.')
                fields(record,SERVER_FIELDS if section=='Servers' else NETWORK_FIELDS)
                if section!='Servers' and record.get('ProxySettings') is not None:
                    fields(record['ProxySettings'],('Squid',))
        shared._validate(doc);render(doc);return doc
    except (ValueError,UnicodeError,TypeError,KeyError,RecursionError,OverflowError) as exc:
        raise DecodeError('Catálogo inválido o incompatible con ALFAISAL Tunnel+ build39.') from exc
