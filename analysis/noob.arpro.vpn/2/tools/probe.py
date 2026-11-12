#!/usr/bin/env python3
"""Original build2 fixed public updater GET; store ciphertext privately only."""
import argparse,hashlib,json
from pathlib import Path
from urllib.request import Request,build_opener,HTTPRedirectHandler
SOURCE='https://jezvpn.xyz/api/app?json=20ec37d9ba9316e8a793'
AGENT='Dalvik/2.1.0 (Linux; U; Android 14)'
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ValueError('Redirect denied')
def classify_response(status,data):
    if status!=200:return 'HTTP_FAILURE'
    if not isinstance(data,bytes) or not data:return 'EMPTY_RESPONSE'
    if len(data)>8*1024*1024:return 'OVERSIZED_RESPONSE'
    if data.lstrip().startswith(b'<'):return 'HTML_NOT_CATALOG'
    return 'CIPHERTEXT_NOT_YET_VERIFIED'
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args()
    a.private.mkdir(parents=True,exist_ok=True,mode=0o700)
    with build_opener(NoRedirect()).open(Request(SOURCE,headers={'User-Agent':AGENT,'Accept-Encoding':'identity'}),timeout=30) as r:
        data=r.read(8*1024*1024+1);assert r.status==200 and 0<len(data)<=8*1024*1024
        report={'source':SOURCE,'status':r.status,'content_type':r.headers.get('Content-Type'),
            'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'html':data.lstrip().startswith(b'<'),
            'outcome':classify_response(r.status,data),
            'authorization':'none in original GET','agent_scope':'analytical HttpURLConnection Android profile, not physical device capture'}
    f=a.private/'remote.enc';f.touch(mode=0o600,exist_ok=True);f.chmod(0o600);f.write_bytes(data)
    (a.private/'probe.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':main()
