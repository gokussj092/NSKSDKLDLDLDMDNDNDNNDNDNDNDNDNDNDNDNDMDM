#!/usr/bin/env python3
"""Download only the fixed updater recovered from build15's raw resource."""
import argparse,hashlib,json,os
from pathlib import Path
from urllib.request import Request,build_opener,HTTPRedirectHandler
SOURCE='https://raw.githubusercontent.com/SpkHexX/HexX/refs/heads/main/AustroTunVPN.json'
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*a,**kw):raise ValueError('REDIRECT_DENIED')
def main():
    p=argparse.ArgumentParser();p.add_argument('output',type=Path);a=p.parse_args()
    with build_opener(NoRedirect()).open(Request(SOURCE,headers={'User-Agent':'AustroPlus VPN/15.0.1','Accept-Encoding':'identity'}),timeout=30) as r:
        if r.status!=200 or r.headers.get('Content-Encoding','identity')!='identity':raise ValueError('INVALID_RESPONSE')
        data=r.read(8*1024*1024+1)
    if not data or len(data)>8*1024*1024 or data.lstrip().startswith(b'<'):raise ValueError('INVALID_CATALOG')
    a.output.parent.mkdir(exist_ok=True,parents=True,mode=0o700)
    with os.fdopen(os.open(a.output,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb') as f:f.write(data)
    print(json.dumps({'httpStatus':200,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'decryptionPerformed':False}))
if __name__=='__main__':main()
