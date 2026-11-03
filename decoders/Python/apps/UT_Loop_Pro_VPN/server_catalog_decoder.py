#!/usr/bin/env python3
"""UT Loop catalogs: fixed original GET, optional official OTA session, signed replies."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from urllib.request import Request, HTTPRedirectHandler, build_opener
from urllib.error import HTTPError

if __package__:
    from .codec import DecodeError, MAX_BYTES, decode_catalog, render
else:
    from codec import DecodeError, MAX_BYTES, decode_catalog, render

CATALOG_URL = 'https://api.utloop.xyz/v1/ota/config?package=loop.uchetechs.vpn.pro'
PREMIUM_URL = 'https://api.utloop.xyz/v1/premium/config'
API_KEY = '4cfKeESbl4NWDsY920ckIfVSag7jn12u3tAH2PWI'


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RemoteError('REMOTE_REDIRECT_REJECTED')


class RemoteError(DecodeError):
    """Safe remote diagnosis, without request credentials or response contents."""
    def __init__(self, code, observation=None):
        super().__init__(code)
        self.code = code
        self.observation = observation or {}


def _observation(status, headers, data):
    return {'httpStatus': status, 'contentType': headers.get('Content-Type', ''),
            'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def download(*, access=None, iid=None, entitlement=None, user_agent='Dalvik/2.1.0') -> bytes:
    """core.h still sends GET if OtaAccess.d returns null; never fabricate access.

    The APK sets no custom User-Agent. The CLI uses the Dalvik prefix; callers
    may supply their own installation's complete platform-generated agent.
    """
    if not isinstance(user_agent, str) or not user_agent or len(user_agent)>2048 or any(
            ord(c)<32 or ord(c)>126 for c in user_agent):
        raise DecodeError('User-Agent incompatible.')
    if entitlement is not None:
        if access is not None or iid is not None:
            raise DecodeError('No mezclar acceso OTA y autorización premium.')
        if not isinstance(entitlement, str) or not entitlement or len(entitlement) > 32768:
            raise DecodeError('Se requiere una autorización premium oficial válida.')
        body = json.dumps({'packageName': 'loop.uchetechs.vpn.pro', 'entitlement': entitlement}).encode('utf-8')
        request = Request(PREMIUM_URL, data=body, headers={'Content-Type': 'application/json'})
    else:
        if (access is None) != (iid is None):
            raise DecodeError('Se requieren acceso OTA e identificador de instalación oficiales.')
        headers = {}
        if access is not None:
            if any(not isinstance(v,str) or not v or len(v)>32768 or any(ord(c)<32 or ord(c)>126 for c in v)
                   for v in (access,iid)):
                raise DecodeError('Acceso OTA o identificador incompatible.')
            headers = {'X-Ota-Access': access, 'X-Ota-Iid': iid}
        request = Request(CATALOG_URL, headers=headers)
    request.add_header('X-Api-Key', API_KEY)
    request.add_header('User-Agent', user_agent)
    request.add_header('Accept-Encoding', 'identity')
    try:
        with build_opener(_NoRedirect()).open(request, timeout=25) as response:
            data = response.read(MAX_BYTES + 1)
            observed = _observation(response.status, response.headers, data)
            if response.status != 200:
                raise RemoteError('REMOTE_HTTP_ERROR', observed)
            if not data or len(data)>MAX_BYTES:
                raise RemoteError('REMOTE_SIZE_INVALID', observed)
            if response.headers.get('Content-Encoding', 'identity') != 'identity':
                raise RemoteError('REMOTE_ENCODING_INVALID', observed)
            if ('html' in observed['contentType'].lower() or data.lstrip().startswith(b'<')):
                raise RemoteError('REMOTE_HTML_RESPONSE', observed)
    except HTTPError as exc:
        data=exc.read(65536)
        observed=_observation(exc.code,exc.headers,data)
        code='REMOTE_AUTH_REJECTED' if exc.code in (401,403) else 'REMOTE_HTTP_ERROR'
        raise RemoteError(code,observed) from None
    except OSError:
        raise RemoteError('REMOTE_NETWORK_ERROR') from None
    # Remote replies MUST carry both a valid app RSA signature and GCM tag.
    try:
        decode_catalog(data, require_signature=True)
    except DecodeError:
        raise RemoteError('REMOTE_SIGNATURE_OR_CATALOG_INVALID',observed) from None
    return data


def run(data: bytes) -> str:
    return render(decode_catalog(data))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    modes = p.add_mutually_exclusive_group(required=True)
    modes.add_argument('file', nargs='?', type=Path, help='Copia local cifrada o sobre firmado')
    modes.add_argument('--stdin', action='store_true')
    modes.add_argument('--download', action='store_true', help='GET original; acceso OTA opcional vía UT_LOOP_OTA_ACCESS / UT_LOOP_OTA_IID')
    modes.add_argument('--premium', action='store_true', help='Autorización oficial vía UT_LOOP_ENTITLEMENT')
    modes.add_argument('--probe', action='store_true', help='GET real; solo diagnóstico y recuentos, sin datos VPN')
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
            data = download(entitlement=entitlement,user_agent=os.environ.get('UT_LOOP_USER_AGENT','Dalvik/2.1.0'))
        else:
            data = download(access=os.environ.get('UT_LOOP_OTA_ACCESS'), iid=os.environ.get('UT_LOOP_OTA_IID'),
                            user_agent=os.environ.get('UT_LOOP_USER_AGENT','Dalvik/2.1.0'))
        if a.probe:
            document=decode_catalog(data,require_signature=True)
            version=document.get('Version')
            if isinstance(version,bool) or not isinstance(version,(str,int)):
                version=None
            report={'status':'success','remoteSignatureVerified':True,'bytes':len(data),
                    'sha256':hashlib.sha256(data).hexdigest(),'version':version,
                    'sections':{k:len(v) for k,v in document.items() if isinstance(v,list)}}
            sys.stdout.write(json.dumps(report,ensure_ascii=False)+'\n')
            return 0
        sys.stdout.write(run(data))
        return 0
    except RemoteError as exc:
        if a.probe:
            print(json.dumps({'status':'error','code':exc.code,**exc.observation}))
        else:
            print('No se pudo descargar el catálogo de UT Loop Pro VPN: '+exc.code, file=sys.stderr)
        return 1
    except (OSError, ValueError):
        if a.probe:
            print(json.dumps({'status':'error','code':'INVALID_CONFIGURATION_OR_RESPONSE'}))
        else:
            print('No se pudo autenticar o leer el catálogo de UT Loop Pro VPN.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
