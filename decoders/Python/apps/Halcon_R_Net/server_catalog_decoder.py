#!/usr/bin/env python3
"""Download the observed build1391 updater or decode its saved encrypted catalog."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import sys
import time
from urllib.parse import urlencode
from urllib.request import Request, HTTPRedirectHandler, build_opener
if __package__:
    from .codec import DecodeError, MAX_BYTES, catalog_password, decode_catalog, render
else:
    from codec import DecodeError, MAX_BYTES, catalog_password, decode_catalog, render

SOURCE = 'https://panel-apk.viofull.com/api_get_config_prod.php'
USER_AGENT = 'Dalvik/2.1.0'
REQUEST_SECRET_ENV = 'SPDECODE_HALCON_REQUEST_SECRET'

def request_data(timestamp=None):
    secret = os.environ.get(REQUEST_SECRET_ENV, '')
    if not re.fullmatch(r'[!-~]{22}', secret):
        raise DecodeError('Acceso del actualizador Halcon no configurado.')
    stamp = str(int(time.time()) if timestamp is None else timestamp)
    if not re.fullmatch(r'[0-9]{1,12}', stamp):
        raise DecodeError('Fecha del actualizador Halcon no válida.')
    signature = hashlib.sha256((stamp + secret).encode()).hexdigest()
    headers = {'User-Agent': USER_AGENT, 'Accept-Encoding': 'identity',
        'Content-Type': 'application/x-www-form-urlencoded', 'X-Auth-Hash': signature,
        'X-Timestamp': stamp, 'X-App-ID': 'HalconRNet_2026'}
    return headers, urlencode({'hash': signature, 'timestamp': stamp}).encode()

class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise DecodeError('El actualizador Halcon intentó redirigir la descarga.')

def download():
    # Fail before DNS when either required secret is absent.
    catalog_password()
    headers, body = request_data()
    try:
        with build_opener(_NoRedirect()).open(Request(SOURCE, data=body, headers=headers), timeout=30) as response:
            if response.status != 200 or response.headers.get('Content-Encoding', 'identity') != 'identity':
                raise DecodeError('Respuesta del actualizador Halcon incompatible.')
            data = response.read(MAX_BYTES + 1)
        if not data or len(data) > MAX_BYTES or data.lstrip().startswith(b'<'):
            raise DecodeError('Respuesta Halcon vacía, HTML o superior al límite.')
        return data
    except OSError as exc:
        raise DecodeError('No se pudo descargar el catálogo Halcon.') from exc

def run(data):
    return render(decode_catalog(data))

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('file', nargs='?', type=Path)
    p.add_argument('--stdin', action='store_true')
    a = p.parse_args()
    if a.file and a.stdin: p.error('Elige archivo o --stdin.')
    try:
        if a.file:
            with a.file.open('rb') as source: data = source.read(MAX_BYTES + 1)
        elif a.stdin: data = sys.stdin.buffer.read(MAX_BYTES + 1)
        else: data = download()
        print(run(data))
        return 0
    except (ValueError, OSError, RecursionError):
        print('No se pudo obtener el catálogo Halcon completo.', file=sys.stderr)
        return 1

if __name__ == '__main__': raise SystemExit(main())
