"""Mx Tunnel PRO Mx-Build48: complete XXTEA catalog, offline."""
from __future__ import annotations
import json
from pathlib import Path
import sys
if __package__ and '.' in __package__:
    from ..HX_Tunnel_VPN import HX_Tunnel_VPN as shared
else:
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
    from HX_Tunnel_VPN import HX_Tunnel_VPN as shared

MAX_BYTES=8*1024*1024
# Recovered from Dm.<clinit> through LSParanoid, not an account credential.
CATALOG_KEY=b'...|...'
LIST_FIELDS=('Free_servers','Premium_servers','Vip_servers','Private_servers','Payloads')


class DecodeError(ValueError):
    """Messages never include catalog contents."""


def decode_catalog(data: bytes) -> dict:
    if not isinstance(data,bytes) or not data or len(data)>MAX_BYTES:
        raise DecodeError('Entrada vacía o superior a 8 MiB.')
    try:
        obj=shared._catalog_json(shared.decrypt_catalog_bytes(data,key=CATALOG_KEY))
        if not isinstance(obj.get('Version'),str) or not obj['Version']:
            raise ValueError('version')
        if any(not isinstance(obj.get(k),list) for k in LIST_FIELDS):
            raise ValueError('sections')
        if not any(obj[k] for k in LIST_FIELDS):raise ValueError('empty catalog')
        return obj
    except (ValueError,UnicodeError,RecursionError,TypeError):
        raise DecodeError('Catálogo inválido o incompatible con Mx Tunnel PRO Mx-Build48.') from None


def render(obj: dict) -> str:
    result=json.dumps(obj,ensure_ascii=False,indent=2,allow_nan=False)+'\n'
    if len(result.encode('utf-8'))>MAX_BYTES:raise DecodeError('La salida supera 8 MiB.')
    return result
