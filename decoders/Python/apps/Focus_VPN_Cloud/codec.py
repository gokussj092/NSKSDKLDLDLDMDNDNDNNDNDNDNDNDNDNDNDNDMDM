"""Focus VPN Cloud 5.0 build 59: block-nibble/AES catalog and RC4 fields."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
from Crypto.Cipher import AES, ARC4
from Crypto.Util.Padding import unpad
if __package__ and '.' in __package__:
    from ..HTTP_FenixVPN import codec as shared
else:
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
    from HTTP_FenixVPN import codec as shared

DecodeError=shared.DecodeError
MAX_BYTES=shared.MAX_BYTES
render=shared.render
ALPHABET='▙▚▛▜▝▞▟▃▄▅▆▇█▉▊▐'
PASSWORD=b'@StrintApp1'
CATALOG_KEY=hashlib.sha256(PASSWORD.hex().upper().encode('ascii')).digest()
# SSLdirecto caches the first key. The catalog consumer initially passes
# String.valueOf(V2Config.secretKeyj), whose initial value is null.
FIELD_KEY=b'null'.ljust(16,b'\0')
SERVER_FIELDS=frozenset(('ServerIP','ServerUser','ServerPass','Payload','SNI',
    'Slowchave','Nameserver','Slowdns','udpBuffer','udpDown','udpUp','UseTcp'))


def decrypt_catalog(data: bytes) -> str:
    text=''.join(shared._bounded(data).decode('utf-8-sig').split())
    if not text or len(text)%2 or any(c not in ALPHABET for c in text):
        raise DecodeError('Alfabeto de catálogo Focus inválido.')
    raw=bytes(ALPHABET.index(text[i])*16+ALPHABET.index(text[i+1]) for i in range(0,len(text),2))
    ciphertext=shared._base64(raw.decode('ascii'))
    if not ciphertext or len(ciphertext)%16:raise DecodeError('Sobre AES Focus inválido.')
    return unpad(AES.new(CATALOG_KEY,AES.MODE_CBC,bytes(16)).decrypt(ciphertext),16).decode('utf-8')


def decode_field(value: str) -> str:
    if value=='':return value
    return ARC4.new(FIELD_KEY).decrypt(shared._base64(value)).decode('utf-8')


def decode_catalog(data: bytes) -> dict:
    try:
        obj=json.loads(decrypt_catalog(data),object_pairs_hook=shared._unique,parse_constant=shared._constant)
        shared._validate(obj)
        if (not isinstance(obj,dict) or not isinstance(obj.get('Version'),str) or not obj['Version']
                or not isinstance(obj.get('Servers'),list) or not obj['Servers']):
            raise DecodeError('Estructura de catálogo Focus inválida.')
        result=obj.copy();servers=[]
        for item in obj['Servers']:
            if not isinstance(item,dict) or not isinstance(item.get('Name'),str):
                raise DecodeError('Perfil Focus inválido.')
            entry=item.copy()
            for field in SERVER_FIELDS & item.keys():
                if not isinstance(item[field],str):raise DecodeError('Campo RC4 Focus inválido.')
                entry[field]=decode_field(item[field])
            servers.append(entry)
        result['Servers']=servers
        shared._validate(result)
        return result
    except (ValueError,UnicodeError,RecursionError,TypeError):
        raise DecodeError('Catálogo inválido o incompatible con Focus VPN Cloud 5.0.') from None
