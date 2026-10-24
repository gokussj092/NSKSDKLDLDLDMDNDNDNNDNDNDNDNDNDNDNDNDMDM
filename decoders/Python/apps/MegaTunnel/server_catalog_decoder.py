#!/usr/bin/env python3
"""Download MegaTunnel 1.17.1's fixed catalog or open an offline copy."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
from urllib.request import Request, HTTPRedirectHandler, build_opener
if __package__:
    from .codec import DecodeError,MAX_BYTES,decode_catalog,render
else:
    from codec import DecodeError,MAX_BYTES,decode_catalog,render

CATALOG_URL='https://raw.githubusercontent.com/SpkHexX/HexX/refs/heads/main/MegaTunnel.js'


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args):raise DecodeError('La fuente fija MegaTunnel intentó redirigir la descarga.')


def download() -> bytes:
    request=Request(CATALOG_URL,headers={'User-Agent':'MegaTunnel/1.17.1','Accept-Encoding':'identity'})
    try:
        with build_opener(_NoRedirect()).open(request,timeout=25) as response:
            if response.status!=200 or response.headers.get('Content-Encoding','identity')!='identity':
                raise DecodeError('Respuesta remota MegaTunnel inválida.')
            data=response.read(MAX_BYTES+1)
    except OSError:
        raise DecodeError('No se pudo descargar el catálogo MegaTunnel autorizado.') from None
    if not data or len(data)>MAX_BYTES or data.lstrip().startswith(b'<'):
        raise DecodeError('Catálogo MegaTunnel vacío, incompatible o superior a 8 MiB.')
    return data


def run(data: bytes) -> str:
    return render(decode_catalog(data))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    modes=parser.add_mutually_exclusive_group()
    modes.add_argument('file',nargs='?',type=Path)
    modes.add_argument('--stdin',action='store_true')
    modes.add_argument('--download',action='store_true')
    args=parser.parse_args()
    try:
        if args.file:
            with args.file.open('rb') as stream:data=stream.read(MAX_BYTES+1)
        elif args.stdin:data=sys.stdin.buffer.read(MAX_BYTES+1)
        else:data=download()
        print(run(data));return 0
    except (OSError,ValueError):
        print('No se pudo descargar o abrir el catálogo MegaTunnel.',file=sys.stderr);return 1


if __name__=='__main__':raise SystemExit(main())
