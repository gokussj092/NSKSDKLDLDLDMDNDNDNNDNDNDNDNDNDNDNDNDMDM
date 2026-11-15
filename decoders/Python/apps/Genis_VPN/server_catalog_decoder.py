#!/usr/bin/env python3
"""Decode one complete Genis catalog or download the exact build76 updater."""
import argparse
import sys
from pathlib import Path
from urllib.request import Request, HTTPRedirectHandler, build_opener

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from decoders.Python.apps.Genis_VPN.codec import DecodeError, MAX_BYTES, decode_catalog, render

SOURCE = 'https://raw.githubusercontent.com/nemygoku/genisvpn/refs/heads/main/genis'
# The updater sets no User-Agent; use an explicit analytical Android profile.
USER_AGENT = 'Dalvik/2.1.0 (Linux; U; Android 14)'


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise DecodeError('Redirección Genis rechazada.')


def download():
    try:
        request = Request(SOURCE, headers={'User-Agent': USER_AGENT, 'Accept-Encoding': 'identity'})
        with build_opener(NoRedirect()).open(request, timeout=30) as response:
            if response.status != 200 or response.headers.get('Content-Encoding', 'identity') != 'identity':
                raise DecodeError('Respuesta Genis inválida.')
            data = response.read(MAX_BYTES+1)
        if not data or len(data)>MAX_BYTES or data.lstrip().startswith(b'<'):
            raise DecodeError('Respuesta Genis vacía, HTML o demasiado grande.')
        return data
    except OSError:
        raise DecodeError('No se pudo descargar el catálogo Genis.') from None


def run(data):
    return render(decode_catalog(data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', nargs='?', type=Path)
    parser.add_argument('--stdin', action='store_true')
    args = parser.parse_args()
    if args.file and args.stdin:
        parser.error('Elegir archivo o --stdin')
    try:
        if args.file:
            with args.file.open('rb') as source:
                data = source.read(MAX_BYTES+1)
        elif args.stdin:
            data = sys.stdin.buffer.read(MAX_BYTES+1)
        else:
            data = download()
        print(run(data))
        return 0
    except (ValueError, OSError, RecursionError):
        print('No se pudo obtener el catálogo Genis VPN completo.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
