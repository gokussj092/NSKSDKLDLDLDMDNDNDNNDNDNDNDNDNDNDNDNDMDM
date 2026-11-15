"""Thailand VPN 1.0.3/build3: original Base64/UTF-8 server response, intact JSON."""
import base64,re
from decoders.Python.apps.BD_NET_VPN.codec import CatalogError,parse_document,render
MAX_BYTES=8*1024*1024

def decode_catalog(data):
    if not isinstance(data,bytes) or not data or len(data)>MAX_BYTES:raise CatalogError('Invalid Thailand input size')
    try:
        compact=re.sub(rb'\s+',b'',data)
        if len(compact)%4 or not re.fullmatch(rb'[A-Za-z0-9+/]+={0,2}',compact):raise ValueError('Base64')
        doc=parse_document(base64.b64decode(compact,validate=True).decode('utf-8'))
        if doc.get('Status') is not True or not isinstance(doc.get('Settings'),dict):raise ValueError('status')
        rows=doc.get('Servers')
        if not isinstance(rows,list) or not rows:raise ValueError('servers')
        for row in rows:
            if (not isinstance(row,dict) or type(row.get('id')) is not int or
                any(not isinstance(row.get(k),str) or not row[k] for k in ('protocol_type','server_name','server_type'))):
                raise ValueError('server')
        # Preserve all configuration, restriction, settings and unknown fields.
        render(doc)
        return doc
    except (ValueError,UnicodeError,TypeError,RecursionError) as error:
        raise CatalogError('Invalid or unsupported Thailand catalog') from error

def run(data):
    result=render(decode_catalog(data))
    if len(result)>4*1024*1024:raise CatalogError('Thailand result exceeds worker limit')
    return result.decode('utf-8')
