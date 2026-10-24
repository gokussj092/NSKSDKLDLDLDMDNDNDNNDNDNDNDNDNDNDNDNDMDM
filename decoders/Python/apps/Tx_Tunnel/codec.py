"""Tx Tunnel v2.17 (70): EO/DOO documents, using the canonical Ultra KDF."""
from __future__ import annotations
import base64
import json
import math
import re

from Crypto.Cipher import AES
from decoders.Python import ultra

MAX_BYTES=8*1024*1024
PROTECTED_FIELDS=frozenset({
    'DefOVPNUser','DefOVPNPass','HysteriaUser','HysteriaOBFS','DefaultOVPNCert',
    'ServerIPHost','OVPNUser','OVPNPass','UDP_obfs','UDP_user','CustomCertificate',
    'SlowDNSHost','SlowDNSKey','V2rayUUID','V2rayPath','TrojanPass',
    'Payload','SNI','CustomProxy','V2rayConfig','BugDNS','V2rayAddress',
    'V2rayHost','V2raySNI','Info','URI',
})

class DecodeError(ValueError):
    pass

def render(obj):
    return json.dumps(obj,ensure_ascii=False,indent=2,allow_nan=False)

def input_text(data):
    if not isinstance(data,bytes) or not data or len(data)>MAX_BYTES:
        raise DecodeError('INVALID_INPUT')
    try:
        text=data.decode('utf-8-sig').strip()
    except UnicodeError as exc:raise DecodeError('INVALID_UTF8') from exc
    if not text:raise DecodeError('INVALID_INPUT')
    return text

def _pairs(items):
    out={}
    for k,v in items:
        if k in out:raise DecodeError('DUPLICATE_JSON_KEY')
        out[k]=v
    return out

def open_envelope(text):
    if not isinstance(text,str) or len(text)>MAX_BYTES:raise DecodeError('INVALID_INPUT')
    try:
        raw=base64.b64decode(text.replace('\r','').replace('\n',''),validate=True)
        if not 44<=len(raw)<=MAX_BYTES:raise ValueError
        profile=ultra.ULTRA_CONFIGS['txtunnel']
        key=ultra.ultra_derive_key(raw[:16],profile['password'],profile['mem'])
        if key is None:raise ValueError
        cipher=AES.new(key,AES.MODE_GCM,nonce=raw[16:28]);cipher.update(raw[:16])
        return cipher.decrypt_and_verify(raw[28:-16],raw[-16:]).decode('utf-8')
    except (ValueError,UnicodeError) as exc:raise DecodeError('INVALID_AUTHENTICATED_ENVELOPE') from exc

def open_document(data):
    text=input_text(data)
    # Keep crypto failures separate: only those may enter the historical reader.
    clear=text if text.startswith('{') else open_envelope(text)
    def invalid(_):raise DecodeError('INVALID_JSON')
    try:
        obj=json.loads(clear,object_pairs_hook=_pairs,parse_constant=invalid)
        render(obj).encode('utf-8')
        if not isinstance(obj,dict):raise ValueError
        return obj
    except (ValueError,UnicodeError,RecursionError) as exc:raise DecodeError('INVALID_DOCUMENT') from exc

def decode_fields(obj):
    cache={};nodes=0
    def walk(x,key='',depth=0):
        nonlocal nodes
        nodes+=1
        if depth>48 or nodes>200000:raise DecodeError('JSON_LIMIT')
        if isinstance(x,dict):return {k:walk(v,k,depth+1) for k,v in x.items()}
        if isinstance(x,list):return [walk(v,'',depth+1) for v in x]
        if isinstance(x,float) and not math.isfinite(x):raise DecodeError('INVALID_JSON')
        if isinstance(x,str) and key in PROTECTED_FIELDS:
            packed=x.replace('\r','').replace('\n','')
            if len(packed)>=60 and re.fullmatch(r'[A-Za-z0-9+/]*={0,2}',packed):
                if packed not in cache:
                    if len(cache)>=8192:raise DecodeError('FIELD_LIMIT')
                    cache[packed]=open_envelope(x)
                return cache[packed]
        return x
    return walk(obj)

def decode_catalog(data):
    obj=open_document(data)
    if (not isinstance(obj.get('Version'),str) or
        not all(isinstance(obj.get(k),list) for k in ('Servers','Networks')) or
        not all(isinstance(v,dict) for k in ('Servers','Networks') for v in obj[k])):
        raise DecodeError('INVALID_TX_CATALOG')
    return decode_fields(obj)
