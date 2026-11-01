#!/usr/bin/env python3
"""Read saved catalogs or repeat the fixed, signed ALFAISAL build39 updater."""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sys
import time
from urllib.parse import urlencode
from urllib.request import Request,HTTPRedirectHandler,build_opener
if __package__:
    from .codec import DecodeError,MAX_BYTES,render,decode_catalog
else:
    from codec import DecodeError,MAX_BYTES,render,decode_catalog

SOURCE='https://panel.alfaisalvpn.com/api/protected_json.php'
METADATA='https://panel.alfaisalvpn.com/api/app_settings.php'
USER_AGENT='ALFAISAL Tunnel+/39'
ENV_NAMES=('SPDECODE_ALFAISAL_API_KEY','SPDECODE_ALFAISAL_SIGNING_KEY','SPDECODE_ALFAISAL_DEVICE_UUID')

def configuration(env):
    values=[env.get(k,'') for k in ENV_NAMES]
    if (any(not isinstance(v,str) or not 16<=len(v)<=512 or
            any(ord(c)<33 or ord(c)>126 for c in v) for v in values) or
        not re.fullmatch(r'[A-Za-z0-9_-]{16,128}',values[2])):
        raise DecodeError('Faltan secretos válidos del actualizador ALFAISAL.')
    return tuple(values)

def signed_request(api_key,signing_key,device_uuid,*,timestamp,nonce):
    body=json.dumps({'device_uuid':device_uuid,'integrity_token':'','integrity_request_id':'',
        'integrity_request_hash':'','integrity_operation':'json_update',
        'json_client_capability':2,'json_direct_requested':1},separators=(',',':')).encode()
    signature=hmac.new(signing_key.encode(),str(timestamp).encode()+b'.'+nonce.encode()+b'.'+body,hashlib.sha256).hexdigest()
    headers={'Content-Type':'application/json; charset=utf-8','Accept':'application/json',
        'Cache-Control':'no-cache','X-API-KEY':api_key,'X-TIMESTAMP':str(timestamp),
        'X-NONCE':nonce,'X-SIGNATURE':signature,'Accept-Encoding':'identity','User-Agent':USER_AGENT}
    return body,headers

class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise DecodeError('La fuente ALFAISAL intentó redirigir la descarga.')

def download() -> bytes:
    api_key,signing_key,client=configuration(os.environ)
    try:
        opener=build_opener(_NoRedirect())
        query=urlencode({'json_client_capability':2,'device_uuid':client})
        request=Request(METADATA+'?'+query,headers={'Accept':'application/json','Accept-Encoding':'identity','User-Agent':USER_AGENT})
        with opener.open(request,timeout=10) as response:
            if response.status!=200 or response.headers.get('Content-Encoding','identity')!='identity':
                raise DecodeError('Metadata ALFAISAL incompatible.')
            raw=response.read(1024*1024+1)
        if not raw or len(raw)>1024*1024:raise DecodeError('Metadata ALFAISAL fuera de límite.')
        meta=json.loads(raw)
        # Honor the current app policy. Never fabricate or bypass attestation.
        if not isinstance(meta,dict) or meta.get('success',True) is not True or meta.get('json_requires_integrity') is not False:
            raise DecodeError('La fuente ALFAISAL requiere otra autorización vigente.')
        body,headers=signed_request(api_key,signing_key,client,timestamp=int(time.time()),nonce=secrets.token_hex(16))
        with opener.open(Request(SOURCE,data=body,headers=headers,method='POST'),timeout=20) as response:
            if response.status!=200 or response.headers.get('Content-Encoding','identity')!='identity':
                raise DecodeError('Respuesta ALFAISAL incompatible.')
            data=response.read(MAX_BYTES+1)
    except (OSError,ValueError,UnicodeError) as exc:
        raise DecodeError('No se pudo descargar el catálogo ALFAISAL con la petición completa.') from exc
    if not data or len(data)>MAX_BYTES or data.lstrip().startswith(b'<'):
        raise DecodeError('Catálogo ALFAISAL vacío o superior al límite.')
    return data

def run(data: bytes) -> str:
    return render(decode_catalog(data))

def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file',nargs='?',type=Path);parser.add_argument('--stdin',action='store_true')
    parser.add_argument('--download',action='store_true',help='GET metadata y POST firmado de la fuente fija')
    a=parser.parse_args()
    if sum((a.file is not None,a.stdin,a.download))!=1:parser.error('Elige un archivo, --stdin o --download.')
    try:
        if a.file:
            with a.file.open('rb') as stream:data=stream.read(MAX_BYTES+1)
        elif a.stdin:data=sys.stdin.buffer.read(MAX_BYTES+1)
        else:data=download()
        print(run(data));return 0
    except (ValueError,OSError,RecursionError):
        print('No se pudo leer el catálogo ALFAISAL completo.',file=sys.stderr);return 1

if __name__=='__main__':raise SystemExit(main())
