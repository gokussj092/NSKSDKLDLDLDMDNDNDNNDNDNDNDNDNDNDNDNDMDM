#!/usr/bin/env python3
"""Download RMP TUNNEL PRO RMP-5's fixed catalog or open an offline copy."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
from urllib.request import Request, HTTPRedirectHandler, build_opener
if __package__:
    from .codec import DecodeError,MAX_BYTES,decode_catalog,render
else:
    from codec import DecodeError,MAX_BYTES,decode_catalog,render

CATALOG_URL='https://raw.githubusercontent.com/pipoyrichards/RMPSYSTEM/refs/heads/main/RMPPRO'


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args):raise DecodeError('La fuente fija RMP TUNNEL PRO intentó redirigir la descarga.')


def download() -> bytes:
    request=Request(CATALOG_URL,headers={'User-Agent':'RMP TUNNEL PRO/RMP-5','Accept-Encoding':'identity'})
    try:
        with build_opener(_NoRedirect()).open(request,timeout=25) as response:
            if response.status!=200 or response.headers.get('Content-Encoding','identity')!='identity':
                raise DecodeError('Respuesta remota RMP TUNNEL PRO inválida.')
            data=response.read(MAX_BYTES+1)
    except OSError:
        raise DecodeError('No se pudo descargar el catálogo RMP TUNNEL PRO autorizado.') from None
    if not data or len(data)>MAX_BYTES or data.lstrip().startswith(b'<'):
        raise DecodeError('Catálogo RMP TUNNEL PRO vacío, incompatible o superior a 8 MiB.')
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
        print('No se pudo descargar o abrir el catálogo RMP TUNNEL PRO.',file=sys.stderr);return 1


if __name__=='__main__':raise SystemExit(main())
