#!/usr/bin/env python3
"""Download only one of the two traced public SpeiGo SV5C sources."""
import argparse,hashlib,json,os
from pathlib import Path
from urllib.request import HTTPRedirectHandler,Request,build_opener
SOURCES={'configs':'https://raw.githubusercontent.com/apksdemons/apks2/refs/heads/main/speigo/servr_speigosx_sv5c','ssh':'https://raw.githubusercontent.com/apksdemons/apks2/refs/heads/main/speigo/user_speigo_sv5c'}
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*a,**kw):raise ValueError('REDIRECT_DENIED')
def probe(kind,path):
    with build_opener(NoRedirect()).open(Request(SOURCES[kind],headers={'User-Agent':'SP-DECODE/1.0','Accept':'application/octet-stream','Accept-Encoding':'identity'}),timeout=25) as r:
        if r.status!=200 or r.headers.get('Content-Encoding','identity')!='identity':raise ValueError('RESPONSE_INVALID')
        raw=r.read(8*1024*1024+1);status=r.status
    if not raw or len(raw)>8*1024*1024:raise ValueError('BODY_BOUNDS')
    path=Path(path)
    with os.fdopen(os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb') as f:f.write(raw)
    report={'source':kind,'url':SOURCES[kind],'httpStatus':status,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'decryptionPerformed':False}
    (path.parent/(kind+'-download-proof.json')).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('source',choices=SOURCES);p.add_argument('output',type=Path);a=p.parse_args();probe(a.source,a.output)
