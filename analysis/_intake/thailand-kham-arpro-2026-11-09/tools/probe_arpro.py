#!/usr/bin/env python3
"""Probe only the recovered original AR PRO catalog; never treat HTTP200 HTML as success."""
import argparse,hashlib,json
from pathlib import Path
from urllib.request import Request,build_opener,HTTPRedirectHandler
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*a,**kw):raise ValueError('REDIRECT')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args()
    source=json.loads((a.private/'embedded-metadata.json').read_text())['DefUpdateURL']
    if source!='https://jezvpn.xyz/api/app?json=743ebcbbf84f7f9cac2f':raise ValueError('SOURCE')
    with build_opener(NoRedirect()).open(Request(source,headers={'User-Agent':'Dalvik/2.1.0 (Linux; U; Android 14)','Accept-Encoding':'identity'}),timeout=30) as response:
        data=response.read(8*1024*1024+1);status=response.status
    if len(data)>8*1024*1024:raise ValueError('SIZE')
    (a.private/'catalog-current.wire').write_bytes(data)
    html=data.lstrip().startswith(b'<')
    proof=dict(status='PENDING' if html else 'NEEDS_VERIFICATION',http=status,bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),
      html=html,siteUnavailable=b'Site Unavailable' in data,remoteCatalogVerified=False,enabled=False)
    (a.private/'probe-summary.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof))
