"""Revision-57 legacy HC records, with original libsodium AEAD framing.

Build 564 JNI primitives and the export declaring verApp 565 are distinct
evidence sources. No ciphertext is accepted by printable-text heuristics here.
"""
from __future__ import annotations
import base64
import hmac
import json
import re
import struct
from Crypto.Cipher import ChaCha20
if __package__:
    from ._hc_hccfg import HCError, _carriers, _poly1305
else:
    from _hc_hccfg import HCError, _carriers, _poly1305

JKL_NATIVE_2=bytes(range(15,-1,-1))+bytes((255,254,253,252))
JKL_NATIVE_3=bytes((8,9,10,11,12,13,14,15,17,17,5,4,3,2,1,0,255,254,253,252))
JKL_NATIVE_4=bytes((237,236,235,234,233,232,231,230,229,228,5,4,3,2,1,0,255,254,253,252))
# Verified double-Base64 field representation in the supplied build-565 export.
JKL_EXPORT_565=bytes((237,236,235,234,233,232,231,230,229,228,213,212,211,210,209,208,207,206,205,204))
SEALED_FIELDS={0,7,10,11,12,17,26,29,30,31}

def open_seal(sealed:bytes,key:bytes,nonce:bytes)->bytes:
    if len(sealed)<16 or len(key)!=32 or len(nonce)!=8:raise HCError('AUTH_FAILED')
    ciphertext,tag=sealed[:-16],sealed[-16:]
    otk=ChaCha20.new(key=key,nonce=nonce).encrypt(bytes(32))
    # Original 64-bit-nonce libsodium construction, not the IETF padded MAC.
    mac=struct.pack('<Q',0)+ciphertext+struct.pack('<Q',len(ciphertext))
    if not hmac.compare_digest(_poly1305(mac,otk),tag):raise HCError('AUTH_FAILED')
    stream=ChaCha20.new(key=key,nonce=nonce);stream.seek(64)
    return stream.decrypt(ciphertext)

def field_layers(value:str,*,json_required=False,representation='export565')->str:
    variants={'export565':(JKL_EXPORT_565,True),'native4':(JKL_NATIVE_4,False),
              'native2':(JKL_NATIVE_2,False),'native3':(JKL_NATIVE_3,False)}
    def valid(text):
        if json_required:
            try:return isinstance(json.loads(text),(dict,list))
            except (ValueError,RecursionError):return False
        return bool(text) and all(c.isprintable() or c in '\r\n\t'for c in text)
    # Readability cannot select a cipher: different XOR representations can
    # all produce plausible text. Select the observed versioned representation.
    key,double=variants[representation]
    try:
        raw=base64.b64decode(value,validate=True)
        raw=bytes(v^key[i%20]for i,v in enumerate(raw))
        if double:raw=base64.b64decode(raw,validate=True)
        decoded=raw.decode('utf-8')
        if valid(decoded):return decoded
    except (ValueError,UnicodeError):pass
    if not json_required or valid(value):return value
    raise HCError('HC_LEGACY57_UNSUPPORTED_FIELD')

def decode(data:bytes):
    if not isinstance(data,(bytes,bytearray)) or not data:return None
    # Delayed import retains the existing HTTPCUSTOM CLI/bot entry points.
    if __package__:
        from .HTTPCUSTOM import HCConstants as C,HCDecryptor as D
    else:
        from HTTPCUSTOM import HCConstants as C,HCDecryptor as D
    xor=bytes.fromhex('e382e4b8adc386f09f9293')
    for logical in _carriers(bytes(data)):
        try:
            outer_hex=bytes(v^xor[i%len(xor)]for i,v in enumerate(logical)).decode('ascii')
            sealed=bytes.fromhex(outer_hex)
            stream=ChaCha20.new(key=C.CHACHA_KEYS[5],nonce=C.STATIC_NONCE);stream.seek(64)
            candidate=json.loads(stream.decrypt(sealed[:-16]).decode('utf-8'))
        except (ValueError,UnicodeError,RecursionError):continue
        cfg=candidate.get('cfg')if isinstance(candidate,dict)else None
        if (not isinstance(cfg,dict) or 'content'not in cfg or
            (candidate.get('verCfg')!=57 and cfg.get('verApp')not in (564,565))):
            continue
        authenticated=json.loads(open_seal(sealed,C.CHACHA_KEYS[5],C.STATIC_NONCE).decode('utf-8'))
        if authenticated!=candidate:raise HCError('AUTH_FAILED')
        if (type(candidate.get('verCfg'))is not int or candidate['verCfg']!=57 or
            type(cfg.get('verApp'))is not int or cfg['verApp']not in (564,565)):
            raise HCError('UNSUPPORTED_VERSION')
        try:content=bytes.fromhex(cfg['content'])
        except (KeyError,TypeError,ValueError)as exc:raise HCError('INVALID_INPUT')from exc
        raw=open_seal(content,C.CHACHA_KEYS[1],C.STATIC_NONCE).decode('utf-8')
        slots=raw.split('[splitConfig]')
        if len(slots)!=32:raise HCError('HC_LEGACY57_UNSUPPORTED_LAYOUT')
        h=str(cfg.get('b')or'');area=str(cfg.get('f')or'')
        material=h+h if h and not area else h+area
        nonce=bytearray(C.STATIC_NONCE);encoded=material.encode('utf-8')[:8];nonce[:len(encoded)]=encoded
        config={};unresolved=[]
        representation='export565'if cfg['verApp']==565 else 'native4'
        for index,token in enumerate(slots):
            label=C.TOKEN_MAP.get(index,f'field_{index}');value=token
            encrypted=bool(re.fullmatch(r'[0-9a-fA-F]{32,}',token)) and len(token)%2==0
            if encrypted:
                opened=None
                for key in C.CHACHA_KEYS:
                    try:opened=open_seal(bytes.fromhex(token),key,bytes(nonce));break
                    except HCError:pass
                if opened is None:
                    # The supplied export has an unresolved historical Psiphon
                    # slot. Keep its exact bytes, label and explicit status.
                    # Never Base64-guess a 16-byte tag into seven garbage chars.
                    if index in SEALED_FIELDS:
                        if index!=17:raise HCError('AUTH_FAILED')
                        unresolved.append({'index':index,'field':label,'status':'encrypted_unresolved'})
                else:
                    value=opened.decode('utf-8')
                    if value:value=field_layers(value,json_required=index==26,representation=representation)
            elif index in SEALED_FIELDS and token and index!=17:
                value=field_layers(token,json_required=index==26,representation=representation)
            if index==7:value=D._process_credentials(value,is_ssh=True)
            elif index==11:value=D._process_credentials(value,is_ssh=False)
            config[label]=value
        protections={}
        for key,label in (('b','hwid'),('f','area')):
            if cfg.get(key):protections[label]=cfg[key]
        result={'Protections':protections,'Config':config,
                'Metadata':{'envelope':{k:v for k,v in candidate.items()if k!='cfg'},
                            'config':{k:v for k,v in cfg.items()if k!='content'}},
                'UnresolvedFields':unresolved}
        return result
    return None
