#!/usr/bin/env python3
"""ProNeet VPN catalogs: offline copies or explicit fixed-source downloads."""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path
import sys
from urllib.request import Request,HTTPRedirectHandler,build_opener
if __package__:
    from .codec import DecodeError,MAX_BYTES,decode_catalog,render,shared
else:
    from codec import DecodeError,MAX_BYTES,decode_catalog,render,shared

SOURCES={
    'usuario':'https://raw.githubusercontent.com/ProNeet-27/ProNet/refs/heads/main/MODO%20USUARIO',
    'token':'https://raw.githubusercontent.com/ProNeet-27/ProNet/refs/heads/main/MODO%20TOKEN',
}
BUNDLE_KIND='spdecode-proneet-vpn-catalogs-v1'


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args):raise DecodeError('La fuente fija ProNeet intentó redirigir la descarga.')


def download(source='usuario') -> bytes:
    if source not in SOURCES:raise DecodeError('Modo ProNeet no reconocido.')
    request=Request(SOURCES[source],headers={'User-Agent':'ProNeet VPN/27.11','Accept-Encoding':'identity'})
    try:
        with build_opener(_NoRedirect()).open(request,timeout=25) as response:
            if response.status!=200 or response.headers.get('Content-Encoding','identity')!='identity':
                raise DecodeError('Respuesta remota ProNeet inválida.')
            data=response.read(MAX_BYTES+1)
    except OSError:
        raise DecodeError('No se pudo descargar el catálogo ProNeet autorizado.') from None
    if not data.strip() or len(data)>MAX_BYTES or data.lstrip().startswith(b'<'):
        raise DecodeError('La fuente ProNeet está vacía, es incompatible o supera 8 MiB.')
    return data


def pack_catalogs(usuario: bytes, token: bytes) -> bytes:
    values={}
    for name,data in [('usuario',usuario),('token',token)]:
        shared._bounded(data);values[name]=base64.b64encode(data).decode('ascii')
    return shared._bounded(json.dumps({'kind':BUNDLE_KIND,'catalogs':values},separators=(',',':')).encode())


def run(data: bytes) -> str:
    """Offline entrypoint; both modes retain independent original documents."""
    try:
        shared._bounded(data)
        if not data.lstrip().startswith(b'{'):return render(decode_catalog(data))
        bundle=json.loads(data,object_pairs_hook=shared._unique,parse_constant=shared._constant)
        if (not isinstance(bundle,dict) or set(bundle)!={'kind','catalogs'} or bundle['kind']!=BUNDLE_KIND
                or not isinstance(bundle['catalogs'],dict) or set(bundle['catalogs'])!=set(SOURCES)):
            raise DecodeError('Sobre dual ProNeet inválido.')
        docs={}
        for name in SOURCES:
            encoded=bundle['catalogs'][name]
            if not isinstance(encoded,str):raise DecodeError('Fuente ProNeet inválida.')
            docs[name]=decode_catalog(base64.b64decode(encoded,validate=True))
        return render({'provider':'proneet-vpn','complete':True,'catalogs':docs})
    except (ValueError,UnicodeError,RecursionError,TypeError):
        raise DecodeError('No se pudo abrir el catálogo completo ProNeet VPN 27.11.') from None


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    modes=parser.add_mutually_exclusive_group()
    modes.add_argument('file',nargs='?',type=Path)
    modes.add_argument('--stdin',action='store_true')
    modes.add_argument('--usuario',action='store_true')
    modes.add_argument('--token',action='store_true')
    modes.add_argument('--all',action='store_true')
    args=parser.parse_args()
    try:
        if args.file:
            with args.file.open('rb') as stream:data=stream.read(MAX_BYTES+1)
        elif args.stdin:data=sys.stdin.buffer.read(MAX_BYTES+1)
        elif args.usuario or args.token:data=download('token' if args.token else 'usuario')
        else:data=pack_catalogs(download('usuario'),download('token'))
        print(run(data));return 0
    except (OSError,ValueError):
        print('No se pudo descargar o abrir el catálogo ProNeet. Las fuentes oficiales pueden estar vacías.',file=sys.stderr);return 1

if __name__=='__main__':raise SystemExit(main())
