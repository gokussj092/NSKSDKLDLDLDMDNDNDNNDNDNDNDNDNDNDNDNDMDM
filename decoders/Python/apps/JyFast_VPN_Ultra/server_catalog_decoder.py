#!/usr/bin/env python3
"""Download a fixed JyFast VPN Ultra 9 mode or decode saved catalog bytes."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
from urllib.request import Request, HTTPRedirectHandler, build_opener

if __package__:
    from .codec import DecodeError, MAX_BYTES, decode_catalog, decode_bundle, render
else:
    from codec import DecodeError, MAX_BYTES, decode_catalog, decode_bundle, render

# Exact ConfigUpdate GET and certificate header from APK 9. No caller URL/ID.
SOURCES = {
    'free': 'http://dev.jenrri.shop:85/ignix_update.php?cfg=free',
    'premium': 'http://dev.jenrri.shop:85/ignix_update.php?cfg=premium',
}
SIGNER_SHA1 = '10c7440b8feac5cee6a54959e7599ff26bd27153'


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DecodeError('El proveedor JyFast intentó redirigir la descarga.')


def download(*, mode='free') -> bytes:
    if mode not in SOURCES:
        raise DecodeError('Modo JyFast no compatible.')
    req = Request(SOURCES[mode], headers={
        'X-IGNIX-SIG': SIGNER_SHA1, 'User-Agent': 'JyFast VPN Ultra/9',
        'Accept-Encoding': 'identity',
    })
    try:
        with build_opener(_NoRedirect()).open(req, timeout=25) as response:
            if response.status != 200 or response.headers.get('Content-Encoding', 'identity') != 'identity':
                raise DecodeError('Respuesta JyFast inválida.')
            data = response.read(MAX_BYTES + 1)
    except OSError as exc:
        raise DecodeError('No se pudo descargar el catálogo JyFast autorizado.') from exc
    if not data or len(data) > MAX_BYTES or data.lstrip().startswith(b'<'):
        raise DecodeError('Catálogo JyFast vacío, incompatible o superior a 8 MiB.')
    return data


def run(data: bytes) -> str:
    """Offline worker: paired catalogs, or a standalone free-mode response."""
    return render(decode_bundle(data) if data.lstrip().startswith(b'{') else decode_catalog(data))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', nargs='?', type=Path)
    parser.add_argument('--stdin', action='store_true')
    parser.add_argument('--mode', choices=tuple(SOURCES), default='free')
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
            data = download(mode=args.mode)
        print(render(decode_bundle(data) if data.lstrip().startswith(b'{')
                     else decode_catalog(data, mode=args.mode)))
        return 0
    except (ValueError, OSError) as exc:
        print(str(exc) if isinstance(exc, DecodeError) else 'No se pudo leer el catálogo JyFast.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
