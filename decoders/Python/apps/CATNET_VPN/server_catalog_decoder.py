#!/usr/bin/env python3
"""Offline CATNET servers JSON or original preflight + fixed public updater."""
import argparse,sys,uuid,time,socket
from pathlib import Path
from urllib.request import Request,build_opener,HTTPRedirectHandler
from urllib.error import HTTPError,URLError
if not __package__:sys.path.insert(0,str(Path(__file__).resolve().parents[4]))
from decoders.Python.apps.CATNET_VPN.codec import CatalogError,MAX_INPUT,parse_document,decode_catalog,run
SOURCE='https://pussyvpn.com/xjvpn/mobile/public/servers'
PREFLIGHT='https://pussyvpn.com/xjvpn/mobile/public/app-update?app_key=pussy_vpn&current_version_code=27'
USER_AGENT='okhttp/4.12.0'
class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise CatalogError('CATNET redirect denied')
def original_headers():
    return {'X-XJ-App-Key':'pussy_vpn','X-App-Key':'pussy_vpn',
        'X-XJ-App-Package':'net.catnet.vpn','X-App-Package':'net.catnet.vpn',
        'X-Package-Name':'net.catnet.vpn','X-XJ-Package-Name':'net.catnet.vpn',
        'X-XJ-Version-Code':'27','X-XJ-Installation-Id':str(uuid.uuid4()),
        'User-Agent':USER_AGENT,'Accept-Encoding':'identity'}
def check_preflight(data):
    doc=parse_document(data.decode('utf-8'));info=doc.get('data')
    if doc.get('success') is not True or not isinstance(info,dict):raise CatalogError('Invalid CATNET preflight')
    if info.get('maintenance') is True:raise CatalogError('CATNET maintenance')
    if info.get('integrity_required') is not False:raise CatalogError('CATNET requires legitimate device verification')
def download():
    headers=original_headers();deadline=time.monotonic()+30
    def get(url,limit):
        for attempt in range(2):
            remaining=deadline-time.monotonic()
            if remaining<=0:raise CatalogError('CATNET deadline exceeded')
            try:reply=opener.open(Request(url,headers=headers),timeout=remaining);break
            except HTTPError as e:
                if attempt==0 and e.code in (502,503,504):e.close();continue
                raise
            except URLError as e:
                if attempt==0 and (isinstance(e.reason,(socket.timeout,ConnectionError)) or getattr(e.reason,'errno',None) in (104,110,111,113,101,32)):continue
                raise
        with reply as r:
            if r.status!=200 or r.headers.get('Content-Encoding','identity')!='identity':
                raise CatalogError('Invalid CATNET HTTP response')
            data=r.read(limit+1)
        if not data or len(data)>limit or data.lstrip().startswith(b'<'):
            raise CatalogError('Empty, HTML or oversized CATNET response')
        return data
    try:
        opener=build_opener(_NoRedirect())
        check_preflight(get(PREFLIGHT,65536))
        data=get(SOURCE,MAX_INPUT);decode_catalog(data);return data
    except (OSError,ValueError,UnicodeError,RecursionError) as e:
        raise CatalogError('Unable to obtain CATNET server catalog') from e
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('file',nargs='?',type=Path)
    p.add_argument('--stdin',action='store_true');a=p.parse_args()
    if a.file and a.stdin:p.error('Choose file or --stdin')
    try:
        if a.file:
            with a.file.open('rb') as f:data=f.read(MAX_INPUT+1)
        elif a.stdin:data=sys.stdin.buffer.read(MAX_INPUT+1)
        else:data=download()
        print(run(data));return 0
    except (ValueError,OSError,RecursionError):
        print('No se pudo obtener el catálogo de servidores CATNET VPN.',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
