"""OpenTunnel build61 .tnl: OPL2 wrapper and PBKDF2-SHA256/AES256-GCM XML.

All original properties, including author restrictions, are preserved verbatim.
Legacy XOR framing is unauthenticated and is kept distinct from GCM framing.
"""
import base64,hashlib,json,re,struct,zlib
import xml.etree.ElementTree as ET
from Crypto.Cipher import AES
MAX_INPUT=8*1024*1024
MAX_CLEAR=4*1024*1024
PASSWORD=b'f3a91c4e2d7b05869e4f1a3c8d2e6b07a5c9f2e14d8b3a76e0f5c1d9b4a72e3f'
LENGTH_MASK=(-1481390639)&0xffffffff
class DecodeError(ValueError):pass
def b64(s):
    s=re.sub(r'[ \t\r\n]','',s);b=base64.b64decode(s,validate=True)
    if base64.b64encode(b).decode()!=s:raise DecodeError('Invalid packing')
    return b
def open_gcm(text):
    parts=text.split('.')
    if len(parts)!=3:raise DecodeError('Invalid envelope')
    salt,nonce,body=map(b64,parts)
    if len(salt)!=32 or len(nonce)!=12 or len(body)<16:raise DecodeError('Invalid envelope size')
    key=hashlib.pbkdf2_hmac('sha256',PASSWORD,salt,100000,32)
    return AES.new(key,AES.MODE_GCM,nonce=nonce).decrypt_and_verify(body[:-16],body[-16:])
def historical_gcm(text):
    """Preserve the pre-existing C0 .tnl framing, selected before decryption.

    Its salt/nonce layout differs from build61. A failed modern tag never
    enters this reader. Historical fragment XML is not a build61 export.
    """
    from ...tnl import PASSWORDS
    salt,nonce,body=map(b64,text.split('.'))
    if not salt or not 8<=len(nonce)<=32 or len(body)<16:raise DecodeError('Invalid historical envelope')
    for password in PASSWORDS['.tnl']:
        key=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,1000,16)
        try:
            return AES.new(key,AES.MODE_GCM,nonce=nonce).decrypt_and_verify(body[:-16],body[-16:])
        except ValueError:continue
    raise DecodeError('Invalid historical tag')
def legacy(text):
    seed=bytes(x^63 for x in [7,6,11,12,122,7,125,7,123,123,122,13,9,9,11,9,8,121,124,13,125,121,10,9,14,8,13,6,9,15])
    key=bytearray((i*29)%255+1 for i in range(32))
    for i,c in enumerate(seed):
        k=key[i%32];key[i%32]=((((k>>5)|(k<<3))^((i+7)*c))^((i*13)%255))&255
    for _ in range(3):
        for i in range(31):key[i]=(key[i]^((key[i]%7)+key[i+1]))&255
    raw=b64(text)
    if len(raw)<8:raise DecodeError('Invalid legacy length')
    nonce,n=struct.unpack_from('>II',raw)
    if n!=len(raw)-8:raise DecodeError('Invalid legacy length')
    out=bytearray()
    for i,c in enumerate(raw[8:]):
        x=c^((i*7+13)&255);out.append((((x<<5)|(x>>3))&255)^key[i%32]^((nonce>>((i%4)*8))&255))
    return bytes(out)
def properties(raw,historical=False):
    if not raw or len(raw)>MAX_CLEAR or b'<!ENTITY' in raw:raise DecodeError('Invalid XML bounds')
    clean=re.sub(br'<!DOCTYPE\s+properties\s+SYSTEM\s+[\x22\x27]http://java.sun.com/dtd/properties.dtd[\x22\x27]\s*>',b'',raw)
    if b'<!DOCTYPE' in clean:raise DecodeError('Unrecognized XML doctype')
    if historical and not clean.lstrip().startswith((b'<?xml',b'<properties')):clean=b'<properties>'+clean+b'</properties>'
    root=ET.fromstring(clean.decode('utf-8-sig'))
    if root.tag!='properties' or root.attrib or len(root)>4097:raise DecodeError('Invalid properties')
    result={}
    for child in root:
        if child.tag=='comment' and not child.attrib and not list(child):continue
        if child.tag!='entry' or set(child.attrib)!={'key'} or list(child):raise DecodeError('Invalid property')
        key=child.attrib['key']
        if not key or key in result:raise DecodeError('Ambiguous properties')
        result[key]=child.text or ''
    if not result or (not historical and result.get('CONFIG_MODE') not in ('1','2','3')):raise DecodeError('Unsupported OpenTunnel properties')
    return result
def decode_file(data):
    try:
        if not isinstance(data,bytes) or not 0<len(data)<=MAX_INPUT:raise DecodeError('Input bounds')
        historical=False
        if data.startswith(b'OPL\x02'):
            if len(data)<12:raise DecodeError('Short OPL')
            n,crc=struct.unpack_from('<II',data,4);n^=LENGTH_MASK
            if n!=len(data)-12:raise DecodeError('OPL length')
            packed=bytes(c^(((195<<(i%8))|(195>>(8-i%8)))&255)^(i&255) for i,c in enumerate(data[12:]))
            if zlib.crc32(packed)&0xffffffff!=crc:raise DecodeError('OPL CRC')
            raw=open_gcm(packed.decode('ascii'))
        else:
            text=data.decode('ascii').strip()
            if '.' in text:
                parts=text.split('.')
                if len(parts)!=3:raise DecodeError('Invalid envelope')
                historical=not (len(b64(parts[0]))==32 and len(b64(parts[1]))==12)
                raw=historical_gcm(text) if historical else open_gcm(text)
            else:raw=legacy(text)
        return properties(raw,historical)
    except (ValueError,TypeError,UnicodeError,ET.ParseError,struct.error,RecursionError):raise DecodeError('Archivo OpenTunnel inválido, dañado o de una versión no compatible.') from None
def run(data):return json.dumps(decode_file(data),ensure_ascii=False,indent=2)
