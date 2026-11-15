"""com.litron.udp build11: complete two-layer CBC catalog, distinct from base.

Both format inputs are public app-wide constants. CBC has no authentication.
Only the nine server keys observed in the APK are opened; other data is kept.
"""
import base64,hashlib,re
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from decoders.Python.apps.BD_NET_VPN.codec import CatalogError,parse_document,render
MAX_INPUT=5*1024*1024
MAX_OUTPUT=4*1024*1024
OUTER_INPUT=b'godtech25'
FIELD_INPUT=b' '*8
FIELDS=frozenset({'ServerHost','Username','Password','Payload','ProxyIP','SNI','ChaveKey','NameServer','DNS'})
def open_value(value,seed):
    if not isinstance(value,str) or not value:raise CatalogError('Invalid Pro ciphertext')
    packed=re.sub(rb'[ \t\r\n]',b'',value.encode('ascii'))
    raw=base64.b64decode(packed,validate=True)
    if not raw or len(raw)%16 or base64.b64encode(raw)!=packed:raise CatalogError('Invalid Pro packing')
    key=hashlib.sha256(seed).digest()
    return unpad(AES.new(key,AES.MODE_CBC,bytes(16)).decrypt(raw),16).decode('utf-8')
def decode_catalog(data):
    try:
        if not isinstance(data,bytes) or not 0<len(data)<=MAX_INPUT:raise CatalogError('Invalid Pro input size')
        obj=parse_document(open_value(data.decode('ascii'),OUTER_INPUT))
        if not isinstance(obj.get('Version'),str) or not obj['Version']:raise CatalogError('Invalid Pro version')
        servers=obj.get('Servers')
        if not isinstance(servers,list) or any(not isinstance(s,dict) or not isinstance(s.get('Name'),str) for s in servers):raise CatalogError('Invalid Pro servers')
        for server in servers:
            for field in FIELDS.intersection(server):
                value=server[field]
                if not isinstance(value,str):raise CatalogError('Invalid Pro field type')
                if value:server[field]=open_value(value,FIELD_INPUT)
        out=render(obj)
        if len(out)>MAX_OUTPUT:raise CatalogError('Pro output exceeds limit')
        return parse_document(out.decode('utf-8'))
    except (ValueError,UnicodeError,TypeError,RecursionError) as exc:
        raise CatalogError('Catálogo Litron Pro VPN inválido o incompatible.') from exc
def run(data):return render(decode_catalog(data)).decode('utf-8')
