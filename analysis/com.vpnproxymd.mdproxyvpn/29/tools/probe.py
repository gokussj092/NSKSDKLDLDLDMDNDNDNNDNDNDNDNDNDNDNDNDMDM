#!/usr/bin/env python3
"""Fetch only the reviewed public MD PROXY source; retain bodies outside Git."""
import argparse,hashlib,json,os
from pathlib import Path
from urllib.request import Request,HTTPRedirectHandler,build_opener
SOURCE='https://strongteam.co/api/ultrasystem/ultrav3.txt'
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*a,**kw):raise ValueError('REDIRECT_DENIED')
def probe(path):
    path=Path(path)
    with build_opener(NoRedirect()).open(Request(SOURCE,headers={'User-Agent':'MD PROXY VPN','Accept-Encoding':'identity'}),timeout=25) as r:
        if r.status!=200 or r.headers.get('Content-Encoding','identity')!='identity':raise ValueError('INVALID_RESPONSE')
        raw=r.read(5*1024*1024+1);status=r.status
    if not raw or len(raw)>5*1024*1024:raise ValueError('BODY_BOUNDS')
    with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as f:f.write(raw)
    report={'source':SOURCE,'httpStatus':status,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'decryptionPerformed':False}
    (path.parent/'download-proof.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('output',type=Path);a=p.parse_args();probe(a.output)
