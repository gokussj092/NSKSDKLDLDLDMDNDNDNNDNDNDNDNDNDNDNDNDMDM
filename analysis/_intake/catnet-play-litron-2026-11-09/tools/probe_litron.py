#!/usr/bin/env python3
"""Fetch the owner's fixed public Litron source; preserve every Unicode byte."""
import argparse,hashlib,json,os
from pathlib import Path
from urllib.request import Request,build_opener,HTTPRedirectHandler
SOURCE='https://godtechprime.github.io/latestv2ray.txt'
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*a,**kw):raise ValueError('REDIRECT_DENIED')
def fetch():
    with build_opener(NoRedirect()).open(Request(SOURCE,headers={'Accept-Encoding':'identity'}),timeout=30) as r:
        if r.status!=200 or r.headers.get('Content-Encoding','identity')!='identity':raise ValueError('INVALID_RESPONSE')
        data=r.read(5*1024*1024+1)
    if not data or len(data)>5*1024*1024 or data.startswith(b'<'):raise ValueError('INVALID_CATALOG')
    return data
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('output',type=Path);a=p.parse_args();data=fetch();a.output.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with os.fdopen(os.open(a.output,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb') as f:f.write(data)
    print(json.dumps({'httpStatus':200,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'decryptionPerformed':False}))
