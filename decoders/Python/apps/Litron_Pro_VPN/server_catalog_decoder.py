#!/usr/bin/env python3
"""Fixed Litron Pro catalog download and complete offline reader."""
import argparse,sys
from pathlib import Path
from urllib.request import Request,build_opener,HTTPRedirectHandler
if not __package__:sys.path.insert(0,str(Path(__file__).resolve().parents[4]))
from decoders.Python.apps.Litron_Pro_VPN.codec import CatalogError,MAX_INPUT,run
SOURCE='https://godtechprime.github.io/litroproadfix.txt'
AGENT='SP-DECODE/1.0'  # Self-identified client; APK uses the platform's default UA.
class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*a,**kw):raise CatalogError('Litron Pro redirect denied')
def download():
    try:
        with build_opener(_NoRedirect()).open(Request(SOURCE,headers={'User-Agent':AGENT,'Accept-Encoding':'identity'}),timeout=25) as r:
            if r.status!=200 or r.headers.get('Content-Encoding','identity')!='identity':raise CatalogError('Invalid Litron Pro response')
            data=r.read(MAX_INPUT+1)
        if not data or len(data)>MAX_INPUT or data.startswith(b'<'):raise CatalogError('Invalid Litron Pro download')
        return data
    except (ValueError,OSError):raise CatalogError('No se pudo descargar el catálogo de Litron Pro VPN.') from None
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('file',nargs='?',type=Path);p.add_argument('--stdin',action='store_true');a=p.parse_args()
    if a.file and a.stdin:p.error('Elige archivo o --stdin.')
    try:
        if a.file:
            with a.file.open('rb') as f:data=f.read(MAX_INPUT+1)
        else:data=sys.stdin.buffer.read(MAX_INPUT+1) if a.stdin else download()
        print(run(data));return 0
    except (ValueError,OSError,RecursionError):print('Catálogo Litron Pro VPN inválido o no disponible.',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
