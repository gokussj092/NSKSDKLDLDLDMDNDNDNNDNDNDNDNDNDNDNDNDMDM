"""NAMO VPN 3.5/code35: XXTEA envelope and explicit Base64/UTF-8 fields.

The build's native format constant is part of this backend module. It is a
decryption-format key, not an HTTP credential or a user/server account secret.
No native code or external files are required at runtime.
"""
import base64,re,struct
from decoders.Python.apps.BD_NET_VPN.codec import CatalogError,MAX_INPUT,parse_document,render

FORMAT_KEY = b'namo090529' # MainDetail.b, static format constant from libapi-namo.so
DELTA=772515655
MASK=0xffffffff
MAX_OUTPUT=4*1024*1024

# sd0.v copies these catalog values into preferences; f60.m decodes them at
# their consumers (x93, SSHCoreService, bo, d81 and MainActivity). No guessing
# from the value's alphabet: names, ports, flags and unknown fields stay intact.
SERVER_FIELDS=('ServerIP','Cloudfront','NameServer','PublicKey','ServerDNS',
    'ProxyIP','Username','Password','setOpenVPN','OvpnCertificate','V2Ray','UDPConfig')
NETWORK_FIELDS=('Sni','ServerDNS','Payload','SquidProxy')

def decode_field(value):
    if not isinstance(value,str):raise CatalogError('Invalid NAMO encoded field type')
    if not value:return value
    try:
        compact=re.sub(rb'\s+',b'',value.encode('ascii'))
        if (not compact or len(compact)%4==1 or
            not re.fullmatch(rb'[A-Za-z0-9+/]*={0,2}',compact) or
            (b'=' in compact and len(compact)%4)):
            raise ValueError('Base64')
        return base64.b64decode(compact+b'='*((-len(compact))%4),validate=True).decode('utf-8')
    except (ValueError,UnicodeError) as e:
        raise CatalogError('Invalid NAMO encoded field') from e

def decode_fields(doc):
    """Decode each documented field once, preserving keys, types and metadata."""
    for rows,fields in [(doc['Servers'],SERVER_FIELDS),(doc['Networks'],NETWORK_FIELDS),
                        ([doc],('setOpenVPN',))]:
        for row in rows:
            for field in fields:
                if field in row:row[field]=decode_field(row[field])
    return doc

def decode_catalog(data: bytes) -> dict:
    if not isinstance(data,bytes) or not data or len(data)>MAX_INPUT:
        raise CatalogError('Invalid NAMO input size')
    try:
        raw=base64.b64decode(re.sub(rb'\s+',b'',data),validate=True)
        if len(raw)<8 or len(raw)%4:raise CatalogError('Invalid NAMO ciphertext size')
        words=list(struct.unpack('<'+'I'*(len(raw)//4),raw));n=len(words)
        key=struct.unpack('<4I',FORMAT_KEY.ljust(16,b'\0')[:16])
        total=((6+52//n)*DELTA)&MASK;y=words[0]
        def mx(z,y,p,e):
            return ((((z>>5)^(y<<2))+((y>>3)^(z<<4)))^((total^y)+(key[(p&3)^e]^z)))&MASK
        while total:
            e=(total>>2)&3
            for p in range(n-1,0,-1):
                words[p]=(words[p]-mx(words[p-1],y,p,e))&MASK;y=words[p]
            words[0]=(words[0]-mx(words[-1],y,0,e))&MASK;y=words[0]
            total=(total-DELTA)&MASK
        size=words[-1]
        if not len(raw)-7<=size<=len(raw)-4 or size>MAX_OUTPUT:
            raise CatalogError('Invalid NAMO plaintext length')
        text=struct.pack('<'+'I'*n,*words)[:size].decode('utf-8')
        doc=parse_document(text)
        if not isinstance(doc.get('Version'),str) or not doc['Version']:
            raise CatalogError('Missing NAMO catalog version')
        for group,name in [('Servers','ServerName'),('Networks','PayloadName')]:
            rows=doc.get(group)
            if not isinstance(rows,list) or not rows or any(not isinstance(r,dict) or
              not isinstance(r.get(name),str) or not r[name] for r in rows):
                raise CatalogError('Invalid NAMO catalog records')
        if 'Message' in doc and not isinstance(doc['Message'],str):
            raise CatalogError('Invalid NAMO message')
        return decode_fields(doc)
    except (ValueError,UnicodeError,TypeError,RecursionError,struct.error) as e:
        raise CatalogError('Invalid or unsupported NAMO catalog') from e

def run(data: bytes) -> str:
    result=render(decode_catalog(data))
    if len(result)>MAX_OUTPUT:raise CatalogError('NAMO result exceeds worker limit')
    return result.decode('utf-8')
