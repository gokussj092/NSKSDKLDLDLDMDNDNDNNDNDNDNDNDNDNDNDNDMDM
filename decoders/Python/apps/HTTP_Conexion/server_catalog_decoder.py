#!/usr/bin/env python3
"""Offline HTTP Conexión decoder or exact observed Firebase-selected updater."""
import argparse,time
from pathlib import Path
import sys
from urllib.request import Request,HTTPRedirectHandler,build_opener
if not __package__:sys.path.insert(0,str(Path(__file__).resolve().parents[4]))
from decoders.Python.apps.HTTP_Conexion.codec import CatalogError,MAX_INPUT,run,pack_catalog
from decoders.Python.apps.HTTP_Conexion.firebase import resolve_config,select_config
SOURCE='https://raw.githubusercontent.com/soportecrisdev/Gen/main/new'
USER_AGENT='HTTP-Conexion-VPN/3.0'
HEADERS={'User-Agent':USER_AGENT,'Accept':'*/*','Cache-Control':'no-cache, no-store, must-revalidate',
 'Pragma':'no-cache','Expires':'0','Accept-Encoding':'identity'}
class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise CatalogError('HTTP Conexión redirect denied')
def download_raw(config):
    config=select_config({'entries':{'ockla_url':config['source'],'gretta_pass':config['password']}})
    try:
        url=config['source']+'?nocache='+str(int(time.time()*1000))
        with build_opener(_NoRedirect()).open(Request(url,headers=HEADERS),timeout=30) as r:
            if r.status!=200 or r.headers.get('Content-Encoding','identity')!='identity':raise CatalogError('Invalid updater response')
            data=r.read(MAX_INPUT+1)
        if not data or len(data)>MAX_INPUT or data.lstrip().startswith(b'<'):raise CatalogError('Empty, HTML or oversized updater')
        return data
    except OSError as e:raise CatalogError('Unable to download HTTP Conexión catalog') from e
def download(*,force=False):
    config=resolve_config(force=force)
    return pack_catalog(download_raw(config),config['password'])
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('file',nargs='?',type=Path)
    p.add_argument('--stdin',action='store_true');a=p.parse_args()
    if a.file and a.stdin:p.error('Choose file or --stdin')
    try:
        if a.file:
            with a.file.open('rb') as f:data=f.read(MAX_INPUT+1)
        elif a.stdin:data=sys.stdin.buffer.read(MAX_INPUT+1)
        else:
            try:print(run(download()));return 0
            except (ValueError,OSError):
                # One fresh pair on a failed download/decode; no obsolete URL/key fallback.
                print(run(download(force=True)));return 0
        print(run(data));return 0
    except (ValueError,OSError,RecursionError):
        print('No se pudo obtener el catálogo HTTP Conexión completo.',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
