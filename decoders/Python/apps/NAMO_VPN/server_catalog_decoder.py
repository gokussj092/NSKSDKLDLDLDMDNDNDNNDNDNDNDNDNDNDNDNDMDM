#!/usr/bin/env python3
"""Offline NAMO catalog decoder or fixed original public updater downloader."""
import argparse
from pathlib import Path
import sys
from urllib.request import Request,HTTPRedirectHandler,build_opener
if not __package__:sys.path.insert(0,str(Path(__file__).resolve().parents[4]))
from decoders.Python.apps.NAMO_VPN.codec import CatalogError,MAX_INPUT,run
SOURCE='https://raw.githubusercontent.com/Anurak2534/ohmvpn/refs/heads/main/newnamo.json'
USER_AGENT='okhttp/5.3.2'
class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise CatalogError('NAMO updater redirect denied')
def download():
    try:
        with build_opener(_NoRedirect()).open(Request(SOURCE,headers={
          'User-Agent':USER_AGENT,'Accept-Encoding':'identity'}),timeout=30) as r:
            if r.status!=200 or r.headers.get('Content-Encoding','identity')!='identity':
                raise CatalogError('Invalid NAMO HTTP response')
            data=r.read(MAX_INPUT+1)
        if not data or len(data)>MAX_INPUT or data.lstrip().startswith(b'<'):
            raise CatalogError('Empty, HTML or oversized NAMO response')
        return data
    except OSError as e:raise CatalogError('Unable to download NAMO catalog') from e
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('file',nargs='?',type=Path)
    p.add_argument('--stdin',action='store_true');a=p.parse_args()
    if a.file and a.stdin:p.error('Choose file or --stdin')
    try:
        if a.file:
            with a.file.open('rb') as f:data=f.read(MAX_INPUT+1)
        elif a.stdin:data=sys.stdin.buffer.read(MAX_INPUT+1)
        else:data=download()
        print(run(data));return 0
    except (ValueError,OSError,RecursionError):
        print('No se pudo obtener el catálogo NAMO VPN completo.',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
