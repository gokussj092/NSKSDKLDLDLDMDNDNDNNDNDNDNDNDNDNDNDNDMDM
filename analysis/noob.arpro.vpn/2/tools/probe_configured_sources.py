#!/usr/bin/env python3
"""Check only the two URLs actually decrypted from the pinned included config.
App-update is metadata only; never download an APK/artifact from its contents.
"""
import argparse,hashlib,json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from urllib.request import Request,build_opener,HTTPRedirectHandler
from urllib.error import HTTPError
SOURCES={'configured-catalog':'https://jezvpn.xyz/api/app?json=743ebcbbf84f7f9cac2f',
    'app-update-metadata':'https://pastebin.com/raw/XrVPE3mj'}
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ValueError('Redirect denied')
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args()
    known=json.loads((a.private/'included-root.json').read_text())
    assert SOURCES['configured-catalog']==known['DefUpdateURL'] and SOURCES['app-update-metadata']==known['updater']
    def get(item):
        name,url=item
        try:r=build_opener(NoRedirect()).open(Request(url,headers={'User-Agent':'Dalvik/2.1.0 (Linux; U; Android 14)','Accept-Encoding':'identity'}),timeout=25)
        except HTTPError as e:r=e
        with r:
            data=r.read(8*1024*1024+1);assert len(data)<=8*1024*1024
            f=a.private/(name+'.response');f.touch(mode=0o600,exist_ok=True);f.chmod(0o600);f.write_bytes(data)
            return {'source':url,'role':name,'http':r.status,'content_type':r.headers.get('Content-Type'),
                'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'html':data.lstrip().startswith(b'<')}
    results=list(ThreadPoolExecutor(max_workers=2).map(get,SOURCES.items()))
    (a.private/'configured-probe.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(results))
if __name__=='__main__':main()
