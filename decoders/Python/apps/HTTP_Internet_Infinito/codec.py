"""HTTP Internet Infinito 1.3.9: WakkoDev/MD5/AES-CBC and ROT22 fields."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
if __package__ and '.' in __package__:
    from ..HTTP_FenixVPN import codec as shared
else:
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
    from HTTP_FenixVPN import codec as shared

DecodeError=shared.DecodeError
MAX_BYTES=shared.MAX_BYTES
render=shared.render
# Build constants recovered from assets/LICENSE, not downloaded credentials.
CATALOG_PASSWORD=b'eDios12@gokum'
FIELD_KEY=b'SonGok@$!sN@gD4l'.ljust(32,b'\0')
NAMES=json.loads(Path(__file__).with_name('field_names.json').read_text('utf-8'))
SERVER_FIELDS=frozenset(NAMES['servers'].values())
USER_FIELDS=frozenset(NAMES['users'].values())


def decrypt_catalog(data: bytes) -> str:
    raw=shared._base64(shared._bounded(data).decode('utf-8-sig').strip())
    if len(raw)<32 or raw[:8]!=b'WakkoDev' or (len(raw)-16)%16:
        raise DecodeError('Sobre WakkoDev inválido.')
    material=previous=b''
    while len(material)<48:
        previous=hashlib.md5(previous+CATALOG_PASSWORD+raw[8:16]).digest()
        material+=previous
    return unpad(AES.new(material[:32],AES.MODE_CBC,material[32:48]).decrypt(raw[16:]),16).decode('utf-8')


def decode_field(value: str) -> str:
    if not isinstance(value,str):raise DecodeError('Campo cifrado inválido.')
    if value=='':return value
    raw=shared._base64(value,urlsafe=True)
    if len(raw)<32 or len(raw)%16:raise DecodeError('Campo AES-CBC inválido.')
    plain=unpad(AES.new(FIELD_KEY,AES.MODE_CBC,raw[:16]).decrypt(raw[16:]),16).decode('utf-8')
    return shared.rotate_java(plain,22)  # assets/LICENSE: INPUT=4


def decode_catalog(data: bytes) -> dict:
    try:
        obj=json.loads(decrypt_catalog(data),object_pairs_hook=shared._unique,parse_constant=shared._constant)
        shared._validate(obj)
        if not isinstance(obj,dict) or not isinstance(obj.get('Version'),str) or not obj['Version']:
            raise DecodeError('Estructura de catálogo inválida.')
        lists=[name for name in ('Servers','Usuarios') if name in obj]
        if not lists:raise DecodeError('El catálogo no contiene perfiles.')
        result=obj.copy()
        for name in lists:
            items=obj[name]
            if not isinstance(items,list) or not items:raise DecodeError('Lista de perfiles inválida.')
            fields=SERVER_FIELDS if name=='Servers' else USER_FIELDS
            display=NAMES['servers']['sName'] if name=='Servers' else 'Name'
            decoded=[]
            for item in items:
                if not isinstance(item,dict) or not isinstance(item.get(display),str):
                    raise DecodeError('Perfil inválido.')
                entry=item.copy()
                for field in fields & item.keys():entry[field]=decode_field(item[field])
                decoded.append(entry)
            result[name]=decoded
        shared._validate(result)
        return result
    except (ValueError,UnicodeError,RecursionError,TypeError):
        raise DecodeError('Catálogo inválido o incompatible con HTTP Internet Infinito 1.3.9.') from None
