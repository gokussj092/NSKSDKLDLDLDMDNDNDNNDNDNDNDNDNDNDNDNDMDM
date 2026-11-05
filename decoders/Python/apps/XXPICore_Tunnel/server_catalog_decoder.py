#!/usr/bin/env python3
"""Offline XXPICore catalog or its single fixed public HTTPS updater."""
import argparse,sys
from pathlib import Path
from urllib.request import Request,HTTPRedirectHandler,build_opener
if not __package__:sys.path.insert(0,str(Path(__file__).resolve().parents[4]))
from decoders.Python.apps.XXPICore_Tunnel.codec import DecodeError,MAX_BYTES,run
CATALOG_URL='https://raw.githubusercontent.com/XyrussProject/infinite88/refs/heads/main/xxpicoretunnel888.hs'
USER_AGENT='Dalvik/2.1.0 (Linux; U; Android 14)'
class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise DecodeError('Redirección no permitida.')
def download():
    try:
        with build_opener(_NoRedirect()).open(Request(CATALOG_URL,headers={'User-Agent':USER_AGENT,'Accept-Encoding':'identity'}),timeout=25) as r:
            if r.status!=200 or r.headers.get('Content-Encoding','identity')!='identity':raise DecodeError('Respuesta remota inválida.')
            data=r.read(MAX_BYTES+1)
    except OSError:raise DecodeError('No se pudo descargar el catálogo autorizado.') from None
    if not data or len(data)>MAX_BYTES or data.lstrip().startswith(b'<'):raise DecodeError('Respuesta vacía, HTML o excesiva.')
    return data
def main():
    p=argparse.ArgumentParser(description=__doc__);m=p.add_mutually_exclusive_group()
    m.add_argument('file',nargs='?',type=Path);m.add_argument('--stdin',action='store_true');m.add_argument('--download',action='store_true');a=p.parse_args()
    try:
        if a.file:
            with a.file.open('rb') as f:data=f.read(MAX_BYTES+1)
        elif a.stdin:data=sys.stdin.buffer.read(MAX_BYTES+1)
        else:data=download()
        sys.stdout.write(run(data));return 0
    except (OSError,ValueError):
        print('No se pudo leer el catálogo completo de XXPICore Tunnel.',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
