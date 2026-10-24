#!/usr/bin/env python3
"""Offline UT Loop catalogs; fixed-source remote mode requires valid official access."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys
from urllib.request import Request, HTTPRedirectHandler, build_opener

if __package__:
    from .codec import DecodeError, MAX_BYTES, decode_catalog, render
else:
    from codec import DecodeError, MAX_BYTES, decode_catalog, render

CATALOG_URL = 'https://api.utloop.xyz/v1/ota/config?package=loop.uchetechs.vpn.pro'
PREMIUM_URL = 'https://api.utloop.xyz/v1/premium/config'
API_KEY = '4cfKeESbl4NWDsY920ckIfVSag7jn12u3tAH2PWI'


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DecodeError('El proveedor intentó redirigir la descarga fija.')


def download(*, access=None, iid=None, entitlement=None) -> bytes:
    """Credentials are supplied by the caller; never generate tokens/attestations."""
    if entitlement is not None:
        if not isinstance(entitlement, str) or not entitlement or len(entitlement) > 32768:
            raise DecodeError('Se requiere una autorización premium oficial válida.')
        body = json.dumps({'packageName': 'loop.uchetechs.vpn.pro', 'entitlement': entitlement}).encode('utf-8')
        request = Request(PREMIUM_URL, data=body, headers={'Content-Type': 'application/json'})
    else:
        if not access or not iid or any(not isinstance(v, str) or len(v) > 32768 or '\r' in v or '\n' in v for v in (access, iid)):
            raise DecodeError('Se requieren acceso OTA e identificador de instalación oficiales.')
        request = Request(CATALOG_URL, headers={'X-Ota-Access': access, 'X-Ota-Iid': iid})
    request.add_header('X-Api-Key', API_KEY)
    request.add_header('User-Agent', 'UT Loop Pro VPN/22.10.26')
    request.add_header('Accept-Encoding', 'identity')
    try:
        with build_opener(_NoRedirect()).open(request, timeout=25) as response:
            if response.status != 200 or response.headers.get('Content-Encoding', 'identity') != 'identity':
                raise DecodeError('Respuesta remota incompatible.')
            data = response.read(MAX_BYTES + 1)
    except OSError:
        raise DecodeError('No se pudo descargar el catálogo autorizado de UT Loop.') from None
    # Remote replies MUST carry both a valid app RSA signature and GCM tag.
    decode_catalog(data, require_signature=True)
    return data


def run(data: bytes) -> str:
    return render(decode_catalog(data))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    modes = p.add_mutually_exclusive_group(required=True)
    modes.add_argument('file', nargs='?', type=Path, help='Copia local cifrada o sobre firmado')
    modes.add_argument('--stdin', action='store_true')
    modes.add_argument('--download', action='store_true', help='Acceso oficial vía UT_LOOP_OTA_ACCESS / UT_LOOP_OTA_IID')
    modes.add_argument('--premium', action='store_true', help='Autorización oficial vía UT_LOOP_ENTITLEMENT')
    a = p.parse_args()
    try:
        if a.file:
            with a.file.open('rb') as stream:
                data = stream.read(MAX_BYTES + 1)
        elif a.stdin:
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        elif a.premium:
            entitlement = os.environ.get('UT_LOOP_ENTITLEMENT')
            if not entitlement:
                raise DecodeError('Se requiere una autorización premium oficial válida.')
            data = download(entitlement=entitlement)
        else:
            data = download(access=os.environ.get('UT_LOOP_OTA_ACCESS'), iid=os.environ.get('UT_LOOP_OTA_IID'))
        sys.stdout.write(run(data))
        return 0
    except (OSError, ValueError):
        print('No se pudo autenticar o leer el catálogo de UT Loop Pro VPN.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
