#!/usr/bin/env python3
"""Read only the APK's fixed public SSH list; never generates an account."""
import argparse,hashlib,json,os
from pathlib import Path
from urllib.request import Request,build_opener,HTTPRedirectHandler
SOURCE='https://api.roosterkid.com/api/opentunnel/servers/'
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*a,**k):raise ValueError('REDIRECT_DENIED')
def probe(output):
    with build_opener(NoRedirect()).open(Request(SOURCE,headers={'User-Agent':'SP-DECODE/1.0','Accept-Encoding':'identity'}),timeout=25) as r:
        status=r.status;data=r.read(8*1024*1024+1)
    if status!=200 or not data or len(data)>8*1024*1024:raise ValueError('INVALID_RESPONSE')
    p=Path(output)
    with os.fdopen(os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as f:f.write(data)
    obj=json.loads(data);result={'source':SOURCE,'status':status,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'rootKeys':list(obj),'serverCount':len(obj.get('servers',[])),'serverFieldNames':sorted({k for r in obj.get('servers',[]) for k in r}),'accountGenerationCalled':False}
    (p.parent/'download-proof.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('output',type=Path);a=p.parse_args();probe(a.output)
