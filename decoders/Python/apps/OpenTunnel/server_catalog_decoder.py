#!/usr/bin/env python3
"""Full public OpenTunnel SSH host list; credentials are per-account, not public."""
import argparse,sys
from pathlib import Path
from urllib.request import Request,build_opener,HTTPRedirectHandler
if not __package__:sys.path.insert(0,str(Path(__file__).resolve().parents[4]))
from decoders.Python.apps.BD_NET_VPN.codec import CatalogError,parse_document,render
MAX_INPUT=8*1024*1024
SOURCE='https://api.roosterkid.com/api/opentunnel/servers/'
class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*a,**kw):raise CatalogError('Redirect denied')
def decode_catalog(data):
    try:
        if not isinstance(data,bytes) or not 0<len(data)<=MAX_INPUT:raise ValueError()
        obj=parse_document(data.decode('utf-8'))
        if not isinstance(obj.get('servers'),list) or not isinstance(obj.get('count'),int) or isinstance(obj['count'],bool) or obj['count']!=len(obj['servers']):raise ValueError()
        if type(obj.get('status')) is not int or obj['status']!=200:raise ValueError()
        if any(not isinstance(r,dict) or not isinstance(r.get('hostname'),str) or not r['hostname'] for r in obj['servers']):raise ValueError()
        return obj
    except (ValueError,UnicodeError,TypeError,RecursionError):raise CatalogError('Listado SSH de OpenTunnel inválido o incompatible.') from None
def run(data):return render(decode_catalog(data)).decode('utf-8')
def download():
    with build_opener(_NoRedirect()).open(Request(SOURCE,headers={'User-Agent':'SP-DECODE/1.0','Accept-Encoding':'identity'}),timeout=25) as r:
        if r.status!=200 or r.headers.get('Content-Encoding','identity')!='identity':raise CatalogError('Invalid response')
        data=r.read(MAX_INPUT+1)
    if not data or len(data)>MAX_INPUT:raise CatalogError('Invalid download')
    return data
def main():
    p=argparse.ArgumentParser();p.add_argument('file',nargs='?',type=Path);p.add_argument('--stdin',action='store_true');a=p.parse_args()
    if a.file and a.stdin:p.error('Elige archivo o --stdin.')
    try:
        if a.file:
            with a.file.open('rb') as f:data=f.read(MAX_INPUT+1)
        else:data=sys.stdin.buffer.read(MAX_INPUT+1) if a.stdin else download()
        print(run(data));return 0
    except (ValueError,OSError):print('Listado SSH de OpenTunnel no disponible.',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
