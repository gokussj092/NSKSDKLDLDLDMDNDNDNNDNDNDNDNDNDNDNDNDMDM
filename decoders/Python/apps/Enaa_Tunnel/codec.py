"""Enaa Tunnel Enna-1.07/7: Argon2id-8192/AES-GCM, exact source field contexts."""
from __future__ import annotations
import base64,json,re,sys
from pathlib import Path
from argon2.low_level import Type,hash_secret_raw
from Crypto.Cipher import AES
if __package__ and '.' in __package__:
    from ..HTTP_FenixVPN import codec as shared
else:
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
    from HTTP_FenixVPN import codec as shared
DecodeError=shared.DecodeError
MAX_BYTES=shared.MAX_BYTES
render=shared.render
PASSWORD=b'WolfTunnelLitePASS'
TOP_FIELDS=('DefOVPNUser','DefOVPNPass','HysteriaUser','HysteriaOBFS','DefaultOVPNCert')
SERVER_FIELDS=('ServerIPHost','OVPNUser','OVPNPass','UDP_obfs','UDP_user','CustomCertificate','SlowDNSHost','SlowDNSKey','V2rayUUID','V2rayPath','H2pass','TrojanPass')
NETWORK_FIELDS=('Payload','CustomProxy','SNI','V2rayConfig','BugDNS','V2rayAddress','V2rayHost','V2raySNI')

def decrypt(text,*,exported=False):
    try:
        if not isinstance(text,str) or not text or len(text.encode())>MAX_BYTES:raise ValueError()
        if exported:
            if len(text)<4 or text[3] not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ':raise ValueError()
            text=text[:3]+text[4:]
        raw=base64.b64decode(text.replace('\r','').replace('\n',''),validate=True)
        if len(raw)<44:raise ValueError()
        key=hash_secret_raw(PASSWORD,raw[:16],3,8192,1,32,Type.ID,version=19)
        cipher=AES.new(key,AES.MODE_GCM,nonce=raw[16:28]);cipher.update(raw[:16])
        return cipher.decrypt_and_verify(raw[28:-16],raw[-16:]).decode('utf-8')
    except (ValueError,UnicodeError,TypeError) as exc:raise DecodeError('Sobre Enaa inválido o incompatible.') from exc

def parse(text):
    try:
        value=json.loads(text,object_pairs_hook=shared._unique,parse_constant=shared._constant)
        shared._validate(value)
        if not isinstance(value,dict):raise ValueError()
        return value
    except (ValueError,UnicodeError,RecursionError) as exc:raise DecodeError('JSON Enaa incompatible.') from exc

def open_document(data,*,exported=False):
    try:text=shared._bounded(data).decode('utf-8-sig').strip()
    except UnicodeError as exc:raise DecodeError('Texto Enaa incompatible.') from exc
    return parse(text if text.startswith('{') else decrypt(text,exported=exported))

def fields(obj,names,cache):
    result=obj.copy()
    for name in names:
        if name not in obj or obj[name] is None:continue
        value=obj[name]
        if not isinstance(value,str):raise DecodeError('Campo Enaa incompatible.')
        packed=value.replace('\r','').replace('\n','')
        # Hometab.Companion.a also accepts plaintext. Shaped encrypted fields
        # must authenticate; an invalid tag never becomes silent partial output.
        if len(packed)>=60 and re.fullmatch(r'[A-Za-z0-9+/]*={0,2}',packed):
            if packed not in cache:
                if len(cache)>=8192:raise DecodeError('Demasiados campos Enaa distintos.')
                cache[packed]=decrypt(value)
            result[name]=cache[packed]
    return result

def decode_catalog(data,*,remote=False):
    obj=open_document(data,exported=remote)
    if (not isinstance(obj.get('Version'),str) or not obj['Version'] or
        any(not isinstance(obj.get(k),list) or not obj[k] for k in ('Servers','Networks'))):
        raise DecodeError('Catálogo Enaa incompleto.')
    cache={};result=fields(obj,TOP_FIELDS,cache)
    for section,names in (('Servers',SERVER_FIELDS),('Networks',NETWORK_FIELDS)):
        result[section]=[]
        for row in obj[section]:
            if not isinstance(row,dict) or not isinstance(row.get('Name'),str):raise DecodeError('Registro Enaa incompatible.')
            result[section].append(fields(row,names,cache))
    shared._validate(result);render(result);return result

def decode_file(data):
    # ConfigFileParser first parseConfig(Encrypt), then DO(EO). Dispatch by
    # envelope length, not by catching a failed authentication tag.
    text=shared._bounded(data).decode('utf-8-sig').strip()
    exported=not text.startswith('{') and len(text.replace('\r','').replace('\n',''))%4==1
    obj=open_document(data,exported=exported)
    if not isinstance(obj.get('Name'),str) or not isinstance(obj.get('TunnelType'),str):raise DecodeError('Perfil Enaa incompatible.')
    result=fields(obj,NETWORK_FIELDS,{})
    shared._validate(result);render(result);return result
