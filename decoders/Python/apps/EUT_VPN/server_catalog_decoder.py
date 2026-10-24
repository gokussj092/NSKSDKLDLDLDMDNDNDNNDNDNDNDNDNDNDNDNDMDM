#!/usr/bin/env python3
"""EUT VPN 2.4.1 catalog reader; downloading requires a valid official session."""
from __future__ import annotations
import argparse
import base64
import json
import os
from pathlib import Path
import re
import sys
from urllib.request import Request, HTTPRedirectHandler, build_opener
from urllib.error import HTTPError
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

if __package__ and '.' in __package__:
    from ..HTTP_FenixVPN import codec as shared
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from HTTP_FenixVPN import codec as shared

DecodeError = shared.DecodeError
MAX_BYTES = shared.MAX_BYTES
CATALOG_URL = 'https://api.eutvpn.com/v5/android/client/get-all-resources'
# sza.b truncates the recovered constant to 16 Java characters, then ISO-8859-1.
KEY = 'fS^]a_DTTj>OU1h&rDx&RUf)-[DmY3Nv'[:16].encode('latin-1')


def _json(text):
    obj = json.loads(text, object_pairs_hook=shared._unique, parse_constant=shared._constant)
    shared._validate(obj)
    return obj


def _open(text: str, *, required=False):
    value = re.sub(r'^eut(?:-settings|-payload)?://', '', text.strip())
    parts = value.split(':')
    if len(parts) != 2:
        if required: raise DecodeError('Sobre de catálogo EUT inválido.')
        return None
    try:
        iv = shared._base64(parts[1])
    except ValueError:
        if required: raise DecodeError('IV del catálogo EUT inválido.') from None
        return None
    if len(iv) != 16:
        if required: raise DecodeError('IV del catálogo EUT inválido.')
        return None
    try:
        ciphertext = shared._base64(parts[0])
        if not ciphertext or len(ciphertext) % 16:
            raise DecodeError('Bloque del catálogo EUT inválido.')
        return unpad(AES.new(KEY, AES.MODE_CBC, iv).decrypt(ciphertext), 16).decode('utf-8')
    except (ValueError, UnicodeError):
        raise DecodeError('No se pudo abrir un bloque del catálogo EUT.') from None


def _walk(obj, depth=0):
    if depth > 64: raise DecodeError('Profundidad superior a 64.')
    if isinstance(obj, dict): return {k: _walk(v, depth+1) for k,v in obj.items()}
    if isinstance(obj, list): return [_walk(v, depth+1) for v in obj]
    if isinstance(obj, str) and obj:
        opened = _open(obj)
        if opened is not None:
            value = _json(opened) if opened.lstrip().startswith(('{','[')) else opened
            return _walk(value, depth+1)
    return obj


def decode_catalog(data: bytes):
    try:
        text = shared._bounded(data).decode('utf-8-sig').strip()
        obj = _json(text) if text.startswith(('{','[')) else _json(_open(text, required=True))
        if not isinstance(obj, (dict,list)) or not obj:
            raise DecodeError('Documento de catálogo EUT vacío o inválido.')
        if isinstance(obj,dict) and not any(k in obj for k in ('SERVER','PAYLOAD','data')):
            raise DecodeError('La respuesta no contiene recursos de catálogo EUT.')
        result = _walk(obj)
        if isinstance(result,dict):
            for name in ('SERVER','PAYLOAD'):
                if name not in result: continue
                resources = result[name]
                if not isinstance(resources,list) or not resources:
                    raise DecodeError('Lista de recursos EUT inválida.')
                for resource in resources:
                    if not isinstance(resource,dict) or not isinstance(resource.get('data'),(list,dict)):
                        raise DecodeError('Recurso EUT sin datos descodificados.')
            if 'data' in result and not isinstance(result['data'],(list,dict)):
                raise DecodeError('Recurso EUT sin datos descodificados.')
        shared._validate(result)
        return result
    except (ValueError,UnicodeError,RecursionError,TypeError):
        raise DecodeError('Catálogo EUT VPN 2.4.1 inválido o incompatible.') from None


def run(data: bytes) -> str:
    """Offline worker entrypoint. Preserves all resources and records without UI filters."""
    return shared.render(decode_catalog(data))


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise DecodeError('La fuente fija EUT intentó redirigir la descarga.')


def download() -> bytes:
    token = os.environ.get('EUT_VPN_ACCESS_TOKEN','')
    payload = os.environ.get('EUT_VPN_REQUEST_JSON','')
    if not token or len(token)>16384 or any(c.isspace() for c in token) or not payload:
        raise DecodeError('Se requieren EUT_VPN_ACCESS_TOKEN y EUT_VPN_REQUEST_JSON de una sesión oficial válida.')
    try:
        body = payload.encode('utf-8')
        if len(body)>65536 or not isinstance(_json(body),dict): raise ValueError()
        request = Request(CATALOG_URL, data=body, headers={'Authorization':'Bearer '+token,
            'Content-Type':'application/json','Accept-Encoding':'identity','User-Agent':'EUT VPN/2.4.1'},method='POST')
        with build_opener(_NoRedirect()).open(request,timeout=25) as response:
            if response.status!=200 or response.headers.get('Content-Encoding','identity')!='identity': raise ValueError()
            return shared._bounded(response.read(MAX_BYTES+1))
    except HTTPError as exc:
        raise DecodeError('La API EUT rechazó la consulta (HTTP '+str(exc.code)+').') from None
    except (OSError,ValueError,UnicodeError):
        raise DecodeError('No se pudo descargar el catálogo EUT autorizado.') from None


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    modes=parser.add_mutually_exclusive_group()
    modes.add_argument('file',nargs='?',type=Path)
    modes.add_argument('--stdin',action='store_true')
    modes.add_argument('--download',action='store_true')
    args=parser.parse_args()
    try:
        if args.file:
            with args.file.open('rb') as stream: data=stream.read(MAX_BYTES+1)
        elif args.stdin: data=sys.stdin.buffer.read(MAX_BYTES+1)
        else: data=download()
        print(run(data));return 0
    except (OSError,ValueError):
        print('No se pudo leer EUT: copia inválida o sesión oficial ausente/rechazada.',file=sys.stderr);return 1


if __name__=='__main__': raise SystemExit(main())
