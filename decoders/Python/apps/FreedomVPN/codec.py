"""FreedomVPN 1.0.29 build 125 catalog; custom-delta XXTEA and mixed fields."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import struct
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
MASK=0xffffffff
DELTA=(-170877363)&MASK
PASSWORD=b'FreedomVPN525'
KEYS={'payload':b'D7FoVFa7UrpkAuc03rQc','user':b'e6iQG0hiMfZWO8aOmLJY',
      'obfs':b'cNEi7mEOyQyxRX5A275J','host':b'eXjaA5SFxj5vr4t1sjql'}
ALPHABET=':;<=>?!"#$%&\'()*'
NIBBLE_FIELDS={'Payload':'payload','SNI':'payload','udpserver':'user',
               'udpobfs':'obfs','v2rayJson':'host','ServerPass':'obfs'}
FIELDS=frozenset(('ServerIP','ServerUser',*NIBBLE_FIELDS))


def xxtea(text: str,key: bytes) -> str:
    raw=shared._base64(text)
    if len(raw)<8 or len(raw)%4:raise DecodeError('Bloque XXTEA FreedomVPN inválido.')
    v=list(struct.unpack('<'+'I'*(len(raw)//4),raw));k=struct.unpack('<4I',key[:16].ljust(16,b'\0'))
    n=len(v);y=v[0];total=((6+52//n)*DELTA)&MASK
    def mix(z,y,p,e):
        return ((((z>>5)^(y<<2))+((y>>3)^(z<<4)))^((total^y)+(k[(p&3)^e]^z)))&MASK
    for _ in range(6+52//n):
        e=(total>>2)&3
        for p in range(n-1,0,-1):v[p]=(v[p]-mix(v[p-1],y,p,e))&MASK;y=v[p]
        v[0]=(v[0]-mix(v[-1],y,0,e))&MASK;y=v[0];total=(total-DELTA)&MASK
    length=v[-1]
    if not 4*n-7<=length<=4*n-4:raise DecodeError('Longitud XXTEA FreedomVPN inválida.')
    return struct.pack('<'+'I'*n,*v)[:length].decode('utf-8')


def decode_field(name: str,value: str) -> str:
    if value=='':return value
    if name=='ServerUser':text=xxtea(value,KEYS['user'])
    elif name=='ServerIP':
        text=unpad(AES.new(KEYS['host'][:16],AES.MODE_ECB).decrypt(shared._base64(value)),16).decode('utf-8')
    else:
        if len(value)%2 or any(c not in ALPHABET for c in value):raise DecodeError('Campo nibble FreedomVPN inválido.')
        raw=bytes(ALPHABET.index(value[i])*16+ALPHABET.index(value[i+1]) for i in range(0,len(value),2))
        key=hashlib.sha256(KEYS[NIBBLE_FIELDS[name]].hex().upper().encode('ascii')).digest()
        text=unpad(AES.new(key,AES.MODE_CBC,bytes(16)).decrypt(shared._base64(raw.decode('ascii'))),16).decode('utf-8')
    return shared.rotate_java(text,25)


def decode_catalog(data: bytes) -> dict:
    try:
        obj=json.loads(xxtea(shared._bounded(data).decode('utf-8-sig'),PASSWORD),
            object_pairs_hook=shared._unique,parse_constant=shared._constant)
        shared._validate(obj)
        if (not isinstance(obj,dict) or not isinstance(obj.get('Version'),str) or not obj['Version']
                or not isinstance(obj.get('Servers'),list) or not obj['Servers']):
            raise DecodeError('Estructura de catálogo FreedomVPN inválida.')
        result=obj.copy();servers=[]
        for item in obj['Servers']:
            if not isinstance(item,dict) or not isinstance(item.get('Name'),str):raise DecodeError('Perfil FreedomVPN inválido.')
            entry=item.copy()
            for name in FIELDS & item.keys():
                if not isinstance(item[name],str):raise DecodeError('Campo FreedomVPN inválido.')
                entry[name]=decode_field(name,item[name])
            servers.append(entry)
        result['Servers']=servers;shared._validate(result);return result
    except (ValueError,UnicodeError,RecursionError,TypeError):
        raise DecodeError('Catálogo inválido o incompatible con FreedomVPN 1.0.29.') from None
