"""MegaTunnel 1.17.1 catalog: authenticated AES-GCM and Base64/XOR fields."""
from __future__ import annotations
import json
from pathlib import Path
import sys
from Crypto.Cipher import AES
if __package__ and '.' in __package__:
    from ..HTTP_FenixVPN import codec as shared
else:
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
    from HTTP_FenixVPN import codec as shared

DecodeError=shared.DecodeError
MAX_BYTES=shared.MAX_BYTES
render=shared.render
# Embedded build constants: G2.confpass, AbstractC2562yx.a and PW.DEFAULT_KEY.
CATALOG_KEY=b'>, java const v1'.ljust(32,b'\0')
FIELD_KEY=b'Abtcji'
FIELDS={
    'Servers':frozenset(('server_host','ws_host','username','password','name_server','dns_pubkey','v2id','v2path')),
    'Tweaks':frozenset(('custom_dns','custom_payload','custom_sni','custom_v2ray','proxy_host')),
}


def decrypt_catalog(data: bytes) -> str:
    raw=shared._base64(shared._bounded(data).decode('utf-8-sig').strip())
    if len(raw)<29:raise DecodeError('Sobre AES-GCM MegaTunnel inválido.')
    cipher=AES.new(CATALOG_KEY,AES.MODE_GCM,nonce=raw[:12],mac_len=16)
    return cipher.decrypt_and_verify(raw[12:-16],raw[-16:]).decode('utf-8')


def decode_field(value: str) -> str:
    if not isinstance(value,str):raise DecodeError('Campo MegaTunnel inválido.')
    if value=='':return value
    raw=shared._base64(value)
    return bytes(byte^FIELD_KEY[i%len(FIELD_KEY)] for i,byte in enumerate(raw)).decode('utf-8')


def decode_catalog(data: bytes) -> dict:
    try:
        obj=json.loads(decrypt_catalog(data),object_pairs_hook=shared._unique,parse_constant=shared._constant)
        shared._validate(obj)
        if not isinstance(obj,dict) or not isinstance(obj.get('version'),str) or not obj['version']:
            raise DecodeError('Versión de catálogo MegaTunnel inválida.')
        result=obj.copy();count=0
        for section,fields in FIELDS.items():
            items=obj.get(section)
            if not isinstance(items,list):raise DecodeError('Sección de catálogo MegaTunnel inválida.')
            decoded=[]
            for item in items:
                if not isinstance(item,dict) or not isinstance(item.get('name'),str):
                    raise DecodeError('Registro de catálogo MegaTunnel inválido.')
                entry=item.copy()
                for field in fields & item.keys():entry[field]=decode_field(item[field])
                decoded.append(entry)
            count+=len(items);result[section]=decoded
        if not count:raise DecodeError('El catálogo MegaTunnel está vacío.')
        shared._validate(result)
        return result
    except (ValueError,UnicodeError,RecursionError,TypeError):
        raise DecodeError('Catálogo inválido o incompatible con MegaTunnel 1.17.1.') from None
