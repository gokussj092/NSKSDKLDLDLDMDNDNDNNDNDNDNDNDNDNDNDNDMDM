"""CATNET builds27/29 public server catalog: complete plain UTF-8 JSON.

This endpoint has no observed encryption layer. Keep all fields and nested
metadata; do not decode strings merely because they resemble Base64 or hex.
Payload/xray catalogs are separate unavailable targets, not part of this API.
"""
from decoders.Python.apps.BD_NET_VPN.codec import CatalogError,MAX_INPUT,parse_document,render
MAX_OUTPUT=4*1024*1024

def decode_catalog(data:bytes)->dict:
    if not isinstance(data,bytes) or not data or len(data)>MAX_INPUT:
        raise CatalogError('Invalid CATNET input size')
    try:
        doc=parse_document(data.decode('utf-8'))
        rows=doc.get('servers')
        if doc.get('success') is not True or not isinstance(rows,list) or not rows:
            raise CatalogError('Invalid CATNET server catalog')
        for row in rows:
            if (not isinstance(row,dict) or type(row.get('id')) is not int or not 0<row['id']<=9007199254740991 or
                any(not isinstance(row.get(k),str) or not row[k] for k in ('servername','ip'))):
                raise CatalogError('Invalid CATNET server record')
        if 'message' in doc and not isinstance(doc['message'],str):raise CatalogError('Invalid CATNET message')
        if 'has_defaults' in doc and type(doc['has_defaults']) is not bool:raise CatalogError('Invalid CATNET defaults flag')
        for key in ('def_user','def_pass_plain','back_user','back_pass_plain'):
            if key in doc and not isinstance(doc[key],str):raise CatalogError('Invalid CATNET defaults')
        return doc
    except (ValueError,UnicodeError,TypeError,RecursionError) as e:
        raise CatalogError('Invalid CATNET server catalog') from e

def run(data:bytes)->str:
    out=render(decode_catalog(data))
    if len(out)>MAX_OUTPUT:raise CatalogError('CATNET result exceeds worker limit')
    return out.decode('utf-8')
