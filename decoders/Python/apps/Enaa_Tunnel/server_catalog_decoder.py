#!/usr/bin/env python3
"""Download the fixed Enaa build 7 source or decode saved catalog bytes."""
import argparse
from pathlib import Path
import sys
from urllib.request import Request, HTTPRedirectHandler, build_opener
if __package__:
    from .codec import DecodeError, MAX_BYTES, decode_catalog, render
else:
    from codec import DecodeError, MAX_BYTES, decode_catalog, render

SOURCE = 'https://strongteam.co/api/wolftunnellite/enaav1.txt'
USER_AGENT = 'Enaa Tunnel'

class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise DecodeError('La fuente Enaa intentó redirigir la descarga.')

def download() -> bytes:
    try:
        req = Request(SOURCE, headers={'User-Agent': USER_AGENT, 'Accept-Encoding': 'identity'})
        with build_opener(_NoRedirect()).open(req, timeout=25) as response:
            if response.status != 200 or response.headers.get('Content-Encoding', 'identity') != 'identity':
                raise DecodeError('Respuesta Enaa incompatible.')
            data = response.read(MAX_BYTES + 1)
    except OSError as exc:
        raise DecodeError('No se pudo descargar el catálogo Enaa.') from exc
    if not data or len(data) > MAX_BYTES or data.lstrip().startswith(b'<'):
        raise DecodeError('Catálogo Enaa vacío o superior al límite.')
    return data

def run(data: bytes) -> str:
    return render(decode_catalog(data, remote=len(data.decode("utf-8-sig").strip().replace("\r", "").replace("\n", "")) % 4 == 1))

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', nargs='?', type=Path)
    parser.add_argument('--stdin', action='store_true')
    parser.add_argument('--download', action='store_true', help='Download the exact fixed updater')
    args = parser.parse_args()
    if sum((args.file is not None,args.stdin,args.download))>1:
        parser.error('Elige archivo o --stdin.')
    try:
        if args.file:
            with args.file.open('rb') as stream:
                data = stream.read(MAX_BYTES + 1)
        elif args.stdin:
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            data = download()
        print(run(data))
        return 0
    except (ValueError, OSError, RecursionError):
        print('No se pudo leer el catálogo Enaa completo.', file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
