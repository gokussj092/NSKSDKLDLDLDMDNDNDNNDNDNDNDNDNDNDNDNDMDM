#!/usr/bin/env python3
"""Trace the owner's build29 and request only its original public server flow."""
import argparse,hashlib,json,os,time,uuid
from pathlib import Path
from urllib.request import Request,build_opener,HTTPRedirectHandler
from urllib.error import HTTPError
BASE='https://pussyvpn.com/xjvpn/'
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*a,**kw):raise ValueError('REDIRECT_DENIED')
def probe(folder):
    folder=Path(folder).resolve();identity=json.loads((folder/'identity.json').read_text())
    if identity['apkSha256']!='870a4e41f11a1cc3987c2f6b098ffa6adb1f69877820065ab7d938b394b39676' or identity['versionCode']!=29:raise ValueError('BUILD_MISMATCH')
    if hashlib.sha256((folder/'base.apk').read_bytes()).hexdigest()!=identity['apkSha256']:raise ValueError('APK_MISMATCH')
    sources=folder/'jadx/sources';checks={
        'net/xj/vpn/api/ApiClient.java':['https://pussyvpn.com/xjvpn/','https://xjdev.net/xjvpn/','pussy_vpn','net.catnet.vpn','X-XJ-Version-Code'],
        'net/xj/vpn/api/MobileApiService.java':['mobile/public/app-update','current_version_code','mobile/public/servers'],
        'defpackage/fe.java':['getIntegrity_required()','setIntegrityVersionCode(29)']}
    hashes={}
    for name,markers in checks.items():
        p=sources/name;text=p.read_text()
        if not all(x in text for x in markers):raise ValueError('SOURCE_TRACE_MISMATCH')
        hashes[name]=hashlib.sha256(p.read_bytes()).hexdigest()
    headers={'X-XJ-App-Key':'pussy_vpn','X-App-Key':'pussy_vpn','X-XJ-App-Package':'net.catnet.vpn','X-App-Package':'net.catnet.vpn',
        'X-Package-Name':'net.catnet.vpn','X-XJ-Package-Name':'net.catnet.vpn','X-XJ-Version-Code':'29',
        'X-XJ-Installation-Id':str(uuid.uuid4()),'User-Agent':'okhttp/4.12.0','Accept-Encoding':'identity'}
    rows=[];opener=build_opener(NoRedirect())
    def get(name,url,limit):
        started=time.monotonic()
        try:r=opener.open(Request(url,headers=headers),timeout=25)
        except HTTPError as e:r=e
        with r:
            data=r.read(limit+1)
            if len(data)>limit:raise ValueError('RESPONSE_BOUNDS')
            status=r.status
        p=folder/(name+'.bin');p.write_bytes(data);p.chmod(0o600)
        rows.append({'source':name,'httpStatus':status,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'seconds':round(time.monotonic()-started,3)})
        try:doc=json.loads(data)
        except (ValueError,UnicodeError):doc=None
        return status,doc
    status,doc=get('preflight',BASE+'mobile/public/app-update?app_key=pussy_vpn&current_version_code=29',65536)
    info=doc.get('data') if isinstance(doc,dict) else None
    if status!=200 or not isinstance(info,dict) or doc.get('success') is not True:outcome='PREFLIGHT_UNAVAILABLE'
    elif info.get('maintenance') is True:outcome='PROVIDER_MAINTENANCE'
    elif info.get('integrity_required') is not False:outcome='REQUIRES_DEVICE'
    else:
        status,doc=get('servers',BASE+'mobile/public/servers',8*1024*1024)
        outcome='DOWNLOADED_REQUIRES_WHOLE_PROOF' if status==200 and isinstance(doc,dict) else 'SERVERS_UNAVAILABLE'
    report={'package':'net.catnet.vpn','build':29,'sourceSha256':hashes,'outcome':outcome,'requests':rows,
        'sameCertificateAsBuild27':identity['certificateSha256']==['dcc1eb6396b9c1b8ec554c99bb8a9ca7feda3a00fee05a977ec186571661c90c'],
        'apkCodeExecuted':False,'integrityBypassed':False}
    (folder/'probe-summary.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();probe(a.private)
