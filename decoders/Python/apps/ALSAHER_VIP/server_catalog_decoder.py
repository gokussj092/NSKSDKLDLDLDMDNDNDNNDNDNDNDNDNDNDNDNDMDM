#!/usr/bin/env python3
"""Download only the fixed original ALSAHER updater or decode saved catalog bytes."""
import argparse
from pathlib import Path
import sys
from urllib.request import Request,HTTPRedirectHandler,build_opener
if __package__:
    from .codec import DecodeError,MAX_BYTES,decode_catalog,render
else:
    from codec import DecodeError,MAX_BYTES,decode_catalog,render

SOURCE='https://raw.githubusercontent.com/Skytells0/Alsaher/main/jihadvip.json'
USER_AGENT='okhttp/4.12.0'

class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise DecodeError('La fuente ALSAHER intentó redirigir la descarga.')

def download():
    try:
        with build_opener(_NoRedirect()).open(Request(SOURCE,headers={
          'User-Agent':USER_AGENT,'Accept-Encoding':'identity'}),timeout=30) as response:
            if response.status!=200 or response.headers.get('Content-Encoding','identity')!='identity':
                raise DecodeError('Respuesta ALSAHER incompatible.')
            data=response.read(MAX_BYTES+1)
        if not data or len(data)>MAX_BYTES or data.lstrip().startswith(b'<'):
            raise DecodeError('Respuesta ALSAHER vacía, HTML o superior al límite.')
        return data
    except OSError as exc:
        raise DecodeError('No se pudo descargar el catálogo ALSAHER.') from exc

def run(data: bytes) -> str:
    return render(decode_catalog(data))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('file',nargs='?',type=Path)
    p.add_argument('--stdin',action='store_true');a=p.parse_args()
    if a.file and a.stdin:p.error('Elige archivo o --stdin.')
    try:
        if a.file:
            with a.file.open('rb') as source:data=source.read(MAX_BYTES+1)
        elif a.stdin:data=sys.stdin.buffer.read(MAX_BYTES+1)
        else:data=download()
        print(run(data));return 0
    except (ValueError,OSError,RecursionError):
        print('No se pudo obtener el catálogo ALSAHER completo.',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
