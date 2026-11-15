#!/usr/bin/env python3
"""Download the fixed Wolf build 16 source or decode saved catalog bytes."""
import argparse
from pathlib import Path
import sys
from urllib.request import Request, HTTPRedirectHandler, build_opener
if __package__:
    from .codec import DecodeError, MAX_BYTES, decode_catalog, render
else:
    from codec import DecodeError, MAX_BYTES, decode_catalog, render

SOURCE = 'https://strongteam.co/api/wolfcustomv2/'
BODY = b'hash=xsandokUpdatex'
USER_AGENT = 'Go-http-client/1.1'

class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise DecodeError('La fuente Wolf intentó redirigir la descarga.')

def download() -> bytes:
    try:
        req = Request(SOURCE, data=BODY, method='POST', headers={'User-Agent': USER_AGENT, 'Accept-Encoding': 'identity', 'Content-Type': 'application/x-www-form-urlencoded'})
        with build_opener(_NoRedirect()).open(req, timeout=25) as response:
            if response.status != 200 or response.headers.get('Content-Encoding', 'identity') != 'identity':
                raise DecodeError('Respuesta Wolf incompatible.')
            data = response.read(MAX_BYTES + 1)
    except OSError as exc:
        raise DecodeError('No se pudo descargar el catálogo Wolf.') from exc
    if not data or len(data) > MAX_BYTES or data.lstrip().startswith(b'<'):
        raise DecodeError('Catálogo Wolf vacío o superior al límite.')
    return data

def run(data: bytes) -> str:
    return render(decode_catalog(data))

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', nargs='?', type=Path)
    parser.add_argument('--stdin', action='store_true')
    args = parser.parse_args()
    if args.file and args.stdin:
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
        print('No se pudo leer el catálogo Wolf completo.', file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())

