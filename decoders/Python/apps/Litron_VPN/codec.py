"""LITRON VPN com.fleet.vpn: Unicode nibble carrier and public CBC catalog.

CBC provides no authenticity. Preserve every source key/type/list and never
strip Unicode carrier characters, some of which are whitespace.
"""
from __future__ import annotations
import base64,hashlib,json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from decoders.Python.apps.BD_NET_VPN.codec import CatalogError,parse_document,render
MAX_INPUT=5*1024*1024
MAX_OUTPUT=4*1024*1024
SEED=b'godtech25'  # Public app-wide format input; not an account credential.
KEY=hashlib.sha256(SEED.hex().upper().encode('ascii')).digest()
IV=bytes(16)
ALPHABET=''.join(chr(0x2000+n) for n in range(16))
def unpack(value):
    if not isinstance(value,str) or not value or len(value)%2:raise CatalogError('Invalid Litron carrier')
    if any(c not in ALPHABET for c in value):raise CatalogError('Invalid Litron alphabet')
    return bytes((ord(value[i])-0x2000)*16+ord(value[i+1])-0x2000 for i in range(0,len(value),2))
def cbc(raw):
    if not raw or len(raw)%16:raise CatalogError('Invalid Litron block length')
    return unpad(AES.new(KEY,AES.MODE_CBC,IV).decrypt(raw),16).decode('utf-8')
def open_outer(data):
    if not isinstance(data,bytes) or not 0<len(data)<=MAX_INPUT:raise CatalogError('Invalid Litron input size')
    # A .strip() here would corrupt this format.
    raw=unpack(data.decode('utf-8'));cipher=base64.b64decode(raw,validate=True)
    if base64.b64encode(cipher)!=raw:raise CatalogError('Noncanonical Litron packing')
    return parse_document(cbc(cipher))
def hidden(value):
    if not value or any(c not in ALPHABET for c in value):return value
    raw=unpack(value);candidates=[]
    try:candidates.append(base64.b64decode(raw,validate=True))
    except ValueError:pass
    candidates.append(raw)
    for candidate in candidates:
        try:return cbc(candidate)
        except (ValueError,UnicodeError):pass
    # Owner-provided helper also understands plain UTF-8 packed as nibbles.
    # An invalid hidden value fails instead of silently returning partial data.
    return raw.decode('utf-8')
def walk(value):
    if isinstance(value,dict):return {k:walk(v) for k,v in value.items()}
    if isinstance(value,list):return [walk(v) for v in value]
    if isinstance(value,str):return hidden(value)
    return value
def decode_catalog(data):
    try:
        obj=open_outer(data)
        if not isinstance(obj.get('Version'),str) or not obj['Version']:raise CatalogError('Invalid Litron version')
        for name in ['Servers','Networks']:
            if not isinstance(obj.get(name),list):raise CatalogError('Invalid Litron sections')
            if any(not isinstance(r,dict) or not isinstance(r.get('Name'),str) for r in obj[name]):raise CatalogError('Invalid Litron record')
        result=walk(obj)
        # Revalidate decrypted text, depth, duplicates/nonfinite and output size.
        out=render(result)
        if len(out)>MAX_OUTPUT:raise CatalogError('Litron output exceeds limit')
        return parse_document(out.decode('utf-8'))
    except (ValueError,UnicodeError,TypeError,RecursionError) as exc:
        raise CatalogError('Catálogo Litron VPN inválido o incompatible.') from exc
def run(data):return render(decode_catalog(data)).decode('utf-8')
