"""ProNeet VPN 27.11: custom Base64/AES-CBC catalog and nested fields."""
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
# AESCrypt.SYMBOLS uses only indices 0..64, including custom padding at 64.
ALPHABET='!?-=∆×÷ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'[:65]
STANDARD='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
CATALOG_KEY=hashlib.sha256(b'Proneet').digest()
FIELD_KEY=hashlib.sha256(b'Key: =Kenova_code').digest()
SERVER_FIELDS=frozenset(('ServerUser','ServerPass','ServerIP','ServerPort','ProxyIP',
    'ProxyPort','SSLPort','Payload','SNI','Slowchave','Nameserver','Slowdns',
    'udpserver','udpauth','udpobfs','udpbuffer','udpdown','udpup','v2rayJson',
    'serverktun','portktun','userktun','passktun'))


def decrypt_text(text: str, key: bytes) -> str:
    if not isinstance(text,str) or not text or any(c not in ALPHABET for c in text):
        raise DecodeError('Alfabeto ProNeet inválido.')
    raw=shared._base64(text.translate(str.maketrans(ALPHABET,STANDARD)))
    if not raw or len(raw)%16:raise DecodeError('Sobre AES-CBC ProNeet inválido.')
    return unpad(AES.new(key,AES.MODE_CBC,bytes(16)).decrypt(raw),16).decode('utf-8')


def decode_field(value: str) -> str:
    if not isinstance(value,str):raise DecodeError('Campo ProNeet inválido.')
    return value if value=='' else decrypt_text(value,FIELD_KEY)


def decode_catalog(data: bytes) -> dict:
    try:
        text=shared._bounded(data).decode('utf-8-sig').strip()
        obj=json.loads(decrypt_text(text,CATALOG_KEY),object_pairs_hook=shared._unique,parse_constant=shared._constant)
        shared._validate(obj)
        if (not isinstance(obj,dict) or not isinstance(obj.get('Version'),str) or not obj['Version']
                or not isinstance(obj.get('Servers'),list) or not obj['Servers']):
            raise DecodeError('Estructura ProNeet inválida.')
        result=obj.copy();servers=[]
        for item in obj['Servers']:
            if not isinstance(item,dict) or not isinstance(item.get('Name'),str):
                raise DecodeError('Servidor ProNeet inválido.')
            entry=item.copy()
            for field in SERVER_FIELDS & item.keys():entry[field]=decode_field(item[field])
            servers.append(entry)
        result['Servers']=servers;shared._validate(result)
        return result
    except (ValueError,UnicodeError,RecursionError,TypeError):
        raise DecodeError('Catálogo inválido o incompatible con ProNeet VPN 27.11.') from None
