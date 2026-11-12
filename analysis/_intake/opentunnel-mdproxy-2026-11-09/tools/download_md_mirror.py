#!/usr/bin/env python3
"""Follow the site's actual public download link, bounded to its HTTPS hosts."""
import argparse,hashlib,json,os,zipfile
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request,build_opener,HTTPRedirectHandler
from io import BytesIO
from androguard.core.apk import APK
from loguru import logger
logger.disable('androguard')
class Redirects(HTTPRedirectHandler):
    def __init__(self):super().__init__();self.hops=0
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        self.hops+=1;v=urlsplit(newurl)
        if self.hops>4 or v.scheme!='https' or not(v.hostname=='apk.dog' or v.hostname.endswith('.apk.dog')) or v.username or v.password or v.port not in (None,443):raise ValueError('REDIRECT_DENIED')
        return super().redirect_request(req,fp,code,msg,headers,newurl)
def acquire(folder):
    folder=Path(folder);report=json.loads((folder/'mirror-discovery.json').read_text());links=[s for s in report['links'] if s.startswith('https://apk.dog/go/?')]
    if len(links)!=1:raise ValueError('DOWNLOAD_LINK_AMBIGUOUS')
    cached=folder/'mirror-response-body.bin'
    if cached.exists():
        raw=cached.read_bytes();metadata=json.loads((folder/'mirror-response.json').read_text())
    else:
        with build_opener(Redirects()).open(Request(links[0],headers={'User-Agent':'Mozilla/5.0','Accept-Encoding':'identity'}),timeout=45) as r:
            metadata={'status':r.status,'type':r.headers.get('Content-Type'),'encoding':r.headers.get('Content-Encoding'),'final':r.url}
            raw=r.read(125*1024*1024+1)
        (folder/'mirror-response.json').write_text(json.dumps(metadata,indent=2)+'\n')
    if metadata['status']!=200 or metadata['encoding'] not in (None,'identity','none'):raise ValueError('RESPONSE_INVALID')
    # This distributor sends literal Content-Encoding:none for an ordinary ZIP.
    # This exception is restricted to static acquisition, never catalog transport.
    if not raw.startswith(b'PK') or len(raw)>125*1024*1024:raise ValueError('DOWNLOAD_BOUNDS')
    p=folder/'distribution.zip'
    if p.exists():
        if p.read_bytes()!=raw:raise ValueError('EXISTING_ARCHIVE_MISMATCH')
    else:
        with os.fdopen(os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as f:f.write(raw)
    from mirror_archive import apk_members
    members=apk_members(raw)
    for name,data in members:
        a=APK(data,raw=True)
        if a.get_package()=='com.vpnproxymd.mdproxyvpn' and a.get_main_activity():
            if int(a.get_androidversion_code())!=29:raise ValueError('UNEXPECTED_BUILD')
            p=folder/'base.apk'
            if p.exists():
                if p.read_bytes()!=data:raise ValueError('EXISTING_BASE_MISMATCH')
            else:
                with os.fdopen(os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as f:f.write(data)
            result={'package':a.get_package(),'versionName':a.get_androidversion_name(),'versionCode':int(a.get_androidversion_code()),'archiveBytes':len(raw),'archiveSha256':hashlib.sha256(raw).hexdigest(),'apkBytes':len(data),'apkSha256':hashlib.sha256(data).hexdigest(),'certificateSha256':sorted(c.sha256.hex() for c in a.get_certificates()),'cryptographicApkSignatureVerified':False,'apkCodeExecuted':False,'sourceCategory':'public mirror, unverified publisher provenance; pinned actual AXML identity','baseArchiveMember':name,'apkMembers':[n for n,_ in members]}
            (folder/'identity.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result));return
    raise ValueError('BASE_NOT_FOUND')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();acquire(a.private)
