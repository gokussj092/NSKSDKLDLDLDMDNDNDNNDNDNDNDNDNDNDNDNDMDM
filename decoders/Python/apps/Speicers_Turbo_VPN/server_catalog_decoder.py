#!/usr/bin/env python3
"""Decode copies or download both fixed app catalogs. No arbitrary URL argument."""
import argparse,base64,json,sys
from pathlib import Path
from urllib.request import Request,HTTPRedirectHandler,build_opener
if not __package__:sys.path.insert(0,str(Path(__file__).resolve().parents[4]))
from decoders.Python.apps.Speicers_Turbo_VPN.codec import DecodeError,MAX_BYTES,decode_catalog,render
CATALOG_URL='https://raw.githubusercontent.com/apksdemons/apks2/refs/heads/main/speicers/spei_servrs'
USERS_URL='https://raw.githubusercontent.com/apksdemons/apks2/refs/heads/main/speicers/spei_users'
BUNDLE_KIND='spdecode-speicers-turbo-vpn-catalogs-v1'
class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise DecodeError('Redirección no permitida.')
def download(*,users=False):
    try:
        req=Request(USERS_URL if users else CATALOG_URL,headers={'User-Agent':'Dalvik/2.1.0 (Linux; U; Android 14)','Accept-Encoding':'identity'})
        with build_opener(_NoRedirect()).open(req,timeout=25) as r:
            if r.status!=200 or r.headers.get('Content-Encoding','identity')!='identity':raise DecodeError('Respuesta remota inválida.')
            data=r.read(MAX_BYTES+1)
        if not data or len(data)>MAX_BYTES or data.lstrip().startswith(b'<'):raise DecodeError('Respuesta vacía, HTML o excesiva.')
        return data
    except OSError:raise DecodeError('No se pudo descargar el catálogo autorizado.') from None
def _unique(pairs):
    result={}
    for k,v in pairs:
        if k in result:raise DecodeError('Paquete ambiguo.')
        result[k]=v
    return result
def pack_catalogs(servers,users):
    if any(not isinstance(x,bytes) or not x or len(x)>MAX_BYTES for x in [servers,users]):raise DecodeError('Catálogo vacío o excesivo.')
    b=json.dumps({'kind':BUNDLE_KIND,'catalogs':{k:base64.b64encode(v).decode() for k,v in [('servers',servers),('users',users)]}},separators=(',',':')).encode()
    if len(b)>MAX_BYTES:raise DecodeError('Paquete excesivo.')
    return b
def decode_bundle(data):
    try:
        if not isinstance(data,bytes) or not data or len(data)>MAX_BYTES:raise DecodeError('Entrada inválida.')
        b=json.loads(data,object_pairs_hook=_unique)
        if not isinstance(b,dict) or set(b)!={'kind','catalogs'} or b['kind']!=BUNDLE_KIND or not isinstance(b['catalogs'],dict) or set(b['catalogs'])!={'servers','users'}:raise DecodeError('Paquete inválido.')
        docs={}
        for name,section in [('servers','Servers'),('users','Usuarios')]:
            if not isinstance(b['catalogs'][name],str):raise DecodeError('Fuente inválida.')
            doc=decode_catalog(base64.b64decode(b['catalogs'][name],validate=True))
            if section not in doc:raise DecodeError('Fuente intercambiada.')
            docs[name]=doc
        return {'provider':'speicers-turbo-vpn','complete':True,'catalogs':docs}
    except (ValueError,UnicodeError,TypeError,RecursionError):raise DecodeError('No se pudieron abrir ambos catálogos completos.') from None
def run(data):return render(decode_bundle(data) if isinstance(data,bytes) and data.lstrip().startswith(b'{') else decode_catalog(data))
def main():
    p=argparse.ArgumentParser(description=__doc__);m=p.add_mutually_exclusive_group();m.add_argument('file',nargs='?',type=Path);m.add_argument('--stdin',action='store_true');m.add_argument('--download',action='store_true');m.add_argument('--users',action='store_true');m.add_argument('--all',action='store_true');a=p.parse_args()
    try:
        if a.file:
            with a.file.open('rb') as f:data=f.read(MAX_BYTES+1)
        elif a.stdin:data=sys.stdin.buffer.read(MAX_BYTES+1)
        elif a.download or a.users:data=download(users=a.users)
        else:data=pack_catalogs(download(),download(users=True))
        print(run(data));return 0
    except (OSError,ValueError):print('No se pudo obtener el catálogo Speicers Turbo completo.',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
