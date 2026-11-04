#!/usr/bin/env python3
"""Original app-update preflight, then three fixed public catalogs if permitted.

No Play token/session is invented. If the server requires Integrity, stop and
report REQUIRES_DEVICE. Responses/installation IDs are private, summaries only.
"""
import argparse,hashlib,json,uuid
from pathlib import Path
from urllib.request import Request,build_opener,HTTPRedirectHandler
from urllib.error import HTTPError
BASE='https://pussyvpn.com/xjvpn/'
PAYLOAD='https://xjdev.net/xjvpn/'
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ValueError('Redirect denied')
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args()
    a.private.mkdir(parents=True,exist_ok=True,mode=0o700)
    installation=str(uuid.uuid4())
    headers={'X-XJ-App-Key':'pussy_vpn','X-App-Key':'pussy_vpn',
        'X-XJ-App-Package':'net.catnet.vpn','X-App-Package':'net.catnet.vpn',
        'X-Package-Name':'net.catnet.vpn','X-XJ-Package-Name':'net.catnet.vpn',
        'X-XJ-Version-Code':'27','X-XJ-Installation-Id':installation,
        'User-Agent':'okhttp/4.12.0','Accept-Encoding':'identity'}
    results=[];opener=build_opener(NoRedirect())
    def get(name,url):
        try:reply=opener.open(Request(url,headers=headers),timeout=30)
        except HTTPError as e:reply=e
        with reply as r:
            data=r.read(8*1024*1024+1)
            if len(data)>8*1024*1024:raise ValueError('Oversized response')
            f=a.private/(name+'.json');f.touch(mode=0o600,exist_ok=True);f.chmod(0o600);f.write_bytes(data)
            row={'source':url,'status':r.status,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
                'content_type':r.headers.get('Content-Type')}
            try:
                doc=json.loads(data);row['json_type']=type(doc).__name__
                if isinstance(doc,dict):row['keys']=list(doc)
            except (ValueError,UnicodeError):doc=None
            results.append(row);return r.status,doc
    status,doc=get('app-update',BASE+'mobile/public/app-update?app_key=pussy_vpn&current_version_code=27')
    info=doc.get('data') if isinstance(doc,dict) else None
    if status!=200 or not isinstance(info,dict) or doc.get('success') is not True:
        outcome='PREFLIGHT_FAILED'
    elif info.get('integrity_required') is not False:
        outcome='REQUIRES_DEVICE'
    else:
        outcome='PREFLIGHT_ALLOWS_PUBLIC_CONFIG'
        for name,url in [('payloads',PAYLOAD+'mobile/public/payloads'),
            ('xray_payloads',PAYLOAD+'mobile/public/xray_payloads'),('servers',BASE+'mobile/public/servers')]:
            get(name,url)
    report={'outcome':outcome,'requests':results,'session_or_token_fabricated':False}
    f=a.private/'probe-summary.json';f.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))
if __name__=='__main__':main()
