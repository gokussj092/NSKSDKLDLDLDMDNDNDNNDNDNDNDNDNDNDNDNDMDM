#!/usr/bin/env python3
"""Tx build-70 catalog: offline reader and exact fixed public GET."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
from urllib.request import Request,HTTPRedirectHandler,build_opener
ROOT=Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from decoders.Python.apps.Tx_Tunnel.codec import DecodeError,MAX_BYTES,decode_catalog,render

# rk1.g formats base.apk's size in MiB to two decimals, then Java Double.toString.
# 28,308,691 / 1,048,576 -> 27.00 -> 27.0; not an account/device credential.
SOURCE='https://strongteam.co/api/txtunnel/v1/?appcode=27.0'
USER_AGENT='Tx Tunnel'

def run(data:bytes)->str:return render(decode_catalog(data))

class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise DecodeError('REMOTE_REDIRECT_REJECTED')

def download():
    req=Request(SOURCE,headers={'User-Agent':USER_AGENT,'Accept-Encoding':'identity'})
    try:
        with build_opener(_NoRedirect()).open(req,timeout=25) as response:
            if response.status!=200 or response.headers.get('Content-Encoding','identity')!='identity':
                raise DecodeError('INVALID_REMOTE_RESPONSE')
            data=response.read(MAX_BYTES+1)
    except OSError as exc:raise DecodeError('REMOTE_UNAVAILABLE') from exc
    if not data or len(data)>MAX_BYTES:raise DecodeError('INVALID_REMOTE_SIZE')
    return data

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('file',nargs='?',help='Catalog path, - for stdin; omitted: fixed GET');a=p.parse_args()
    try:
        if a.file=='-':data=sys.stdin.buffer.read(MAX_BYTES+1)
        elif a.file:
            with Path(a.file).open('rb') as f:data=f.read(MAX_BYTES+1)
        else:data=download()
        print(run(data));return 0
    except (ValueError,OSError,RecursionError):
        print('No se pudo leer el catálogo Tx Tunnel completo.',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
