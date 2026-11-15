#!/usr/bin/env python3
"""Fixed SpeiGo configurations reader; the SSH source has its own entry point."""
import argparse,sys
from pathlib import Path
from urllib.request import Request,build_opener,HTTPRedirectHandler
if not __package__:sys.path.insert(0,str(Path(__file__).resolve().parents[4]))
from decoders.Python.apps.SpeiGo_VPN.codec import DecodeError,MAX_BYTES,decode_catalog,render
SOURCES={1:'https://raw.githubusercontent.com/apksdemons/apks2/refs/heads/main/speigo/servr_speigosx_sv5c',2:'https://raw.githubusercontent.com/apksdemons/apks2/refs/heads/main/speigo/user_speigo_sv5c'}
class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*a,**kw):raise DecodeError('SpeiGo redirect denied')
def download(purpose=1):
    if purpose not in SOURCES:raise DecodeError('Invalid SpeiGo source')
    try:
        with build_opener(_NoRedirect()).open(Request(SOURCES[purpose],headers={'User-Agent':'SP-DECODE/1.0','Accept':'application/octet-stream','Accept-Encoding':'identity'}),timeout=25) as r:
            if r.status!=200 or r.headers.get('Content-Encoding','identity')!='identity':raise DecodeError('Invalid SpeiGo response')
            data=r.read(MAX_BYTES+1)
        if not data or len(data)>MAX_BYTES or data.startswith(b'<'):raise DecodeError('Invalid SpeiGo response')
        return data
    except (ValueError,OSError):raise DecodeError('No se pudo descargar el catálogo de SpeiGo VPN.') from None
def run(data):return render(decode_catalog(data,1))
def main(purpose=1):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('file',nargs='?',type=Path);p.add_argument('--stdin',action='store_true');a=p.parse_args()
    if a.file and a.stdin:p.error('Elige archivo o --stdin.')
    try:
        if a.file:
            with a.file.open('rb') as f:data=f.read(MAX_BYTES+1)
        else:data=sys.stdin.buffer.read(MAX_BYTES+1) if a.stdin else download(purpose)
        print(render(decode_catalog(data,purpose)));return 0
    except (ValueError,OSError,RecursionError):print('Catálogo SpeiGo VPN inválido o no disponible.',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
