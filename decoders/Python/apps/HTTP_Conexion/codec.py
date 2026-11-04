"""HTTP Conexión 1.2.9/129: glyph/CBC catalog and authenticated GCM/ROT34 fields.

Format constants are stored in this backend module. No external key file or
HTTP credential is required. Never treat a failed GCM tag as plaintext success.
"""
import base64,hashlib,re
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from decoders.Python.apps.BD_NET_VPN.codec import CatalogError,MAX_INPUT,parse_document,render

CATALOG_PASSWORD = b'\xc2\xa9risdev~' # pinned APK format constant; not HTTP authentication
FIELD_KEY = b'edfgbh,lopijyt,k' # pinned APK format constant; not HTTP authentication
GLYPHS=base64.b64decode('4paZ4paa4pab4pac4pad4pae4paf4paD4paE4paF4paG4paH4paI4paJ4paK4paQ').decode()
ROT='0123456789ABCDEFGHJKLMNPQRSTUVWXYZ'
GCM_FIELDS=frozenset({'ServerIP','ServerUser','ServerPass','Payload','SNI','udpBuffer','udpUp','udpDown',
 'Slowchave','Nameserver','Slowdns','UseTcp','udpObfs','v2rayAddress','v2rayPort','v2rayUuid',
 'v2rayServerName','v2rayHost','v2rayPath','v2rayProtocol','v2rayNetwork','v2raySecurity','v2rayFlow',
 'v2rayPublicKey','v2rayShortId','v2rayObfs','zivpnPassword'})
MAX_OUTPUT=4*1024*1024

def _base64(value):
    if not isinstance(value,(str,bytes)):raise CatalogError('Expected HTTP Conexión Base64 text')
    raw=value.encode('ascii') if isinstance(value,str) else value
    return base64.b64decode(re.sub(rb'[\t\n\r ]+',b'',raw),validate=True)

def open_outer(data: bytes) -> dict:
    if not isinstance(data,bytes) or not data or len(data)>MAX_INPUT:
        raise CatalogError('Invalid HTTP Conexión input size')
    try:
        text=data.decode('utf-8-sig').strip()
        if not text or len(text)%2 or any(x not in GLYPHS for x in text):raise ValueError('glyph')
        raw=bytes(GLYPHS.index(text[i])*16+GLYPHS.index(text[i+1]) for i in range(0,len(text),2))
        cipher=_base64(raw)
        if not cipher or len(cipher)%16:raise ValueError('CBC size')
        key=hashlib.sha256(CATALOG_PASSWORD.hex().upper().encode('ascii')).digest()
        clear=unpad(AES.new(key,AES.MODE_CBC,bytes(16)).decrypt(cipher),16)
        if len(clear)>MAX_OUTPUT:raise ValueError('output size')
        doc=parse_document(clear.decode('utf-8'))
        if not isinstance(doc.get('Version'),str) or not doc['Version']:raise ValueError('version')
        if 'ReleaseNotes' in doc and not isinstance(doc['ReleaseNotes'],str):raise ValueError('notes')
        rows=doc.get('Servers')
        if not isinstance(rows,list) or not rows or any(not isinstance(r,dict) or
          not isinstance(r.get('Name'),str) or not r['Name'] for r in rows):raise ValueError('servers')
        return doc
    except (ValueError,UnicodeError,TypeError,RecursionError) as e:
        raise CatalogError('Invalid HTTP Conexión catalog envelope') from e

def decode_field(value: str) -> str:
    if value=='':return value
    try:
        raw=_base64(value)
        if len(raw)<28:raise ValueError('GCM size')
        clear=AES.new(FIELD_KEY,AES.MODE_GCM,nonce=raw[:12],mac_len=16).decrypt_and_verify(raw[12:-16],raw[-16:])
        shifted=_base64(clear).decode('utf-8')
        return ''.join(ROT[(ROT.index(c)+33)%34] if c in ROT else c for c in shifted)
    except (ValueError,UnicodeError,TypeError) as e:
        raise CatalogError('Invalid authenticated HTTP Conexión field') from e

def decode_catalog(data: bytes) -> dict:
    doc=open_outer(data);cache={}
    for row in doc['Servers']:
        for key in GCM_FIELDS & row.keys():
            value=row[key]
            if not isinstance(value,str):raise CatalogError('Invalid HTTP Conexión field type')
            if value not in cache:cache[value]=decode_field(value)
            row[key]=cache[value]
    return doc

def run(data: bytes) -> str:
    result=render(decode_catalog(data))
    if len(result)>MAX_OUTPUT:raise CatalogError('HTTP Conexión output exceeds worker limit')
    return result.decode('utf-8')
