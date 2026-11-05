#!/usr/bin/env python3
"""GET the fixed public URL used by build 118; retain bytes privately."""
import argparse,hashlib,json
from pathlib import Path
from urllib.request import Request,build_opener,HTTPRedirectHandler
from urllib.error import HTTPError
URL='https://raw.githubusercontent.com/XyrussProject/infinite88/refs/heads/main/xxpicoretunnel888.hs'
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ValueError('Redirect denied')
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args()
    a.private.mkdir(parents=True,exist_ok=True,mode=0o700)
    try:r=build_opener(NoRedirect()).open(Request(URL,headers={'Accept-Encoding':'identity'}),timeout=30)
    except HTTPError as e:r=e
    with r:
        data=r.read(8*1024*1024+1)
        if len(data)>8*1024*1024:raise ValueError('Oversized body')
        f=a.private/'remote.bin';f.touch(mode=0o600,exist_ok=True);f.chmod(0o600);f.write_bytes(data)
        result={'url':URL,'http_status':r.status,'content_type':r.headers.get('Content-Type'),'bytes':len(data),
            'sha256':hashlib.sha256(data).hexdigest(),'authentication':'public; no token or session','app_headers':'no custom headers in Q(boolean)'}
    (a.private/'probe-summary.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
