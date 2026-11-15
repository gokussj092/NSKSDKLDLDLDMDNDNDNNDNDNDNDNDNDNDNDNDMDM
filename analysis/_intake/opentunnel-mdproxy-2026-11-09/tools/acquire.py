#!/usr/bin/env python3
"""Bounded public-distribution acquisition for exactly the two requested apps."""
import argparse,hashlib,importlib.util,json,zipfile
from io import BytesIO
from pathlib import Path
from androguard.core.apk import APK
from loguru import logger
logger.disable('androguard')
ROOT=Path(__file__).resolve().parents[4]
PACKAGES={'open':'com.opentunnel.app','mdproxy':'com.vpnproxymd.mdproxyvpn'}
def acquire(kind,folder,build=None,apk_only=False):
    package=PACKAGES[kind];path=ROOT/'analysis/com.tunneldoom.http/432/tools/acquire.py'
    s=importlib.util.spec_from_file_location('bounded_distribution_acquirer',path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
    m.SOURCE='https://d.apkpure.net/b/'+('APK' if apk_only else 'XAPK')+'/'+package+'?'+('version=latest' if build is None else 'versionCode='+str(build))
    folder=Path(folder);folder.mkdir(parents=True,exist_ok=True,mode=0o700);folder.chmod(0o700);p=folder/'distribution.xapk'
    if p.is_symlink():raise ValueError('UNSAFE_INPUT')
    data=p.read_bytes() if p.exists() else m.fetch_xapk()
    if not data or len(data)>m.MAX_BYTES:raise ValueError('XAPK_BOUNDS')
    if not p.exists():m.save_private(data,p)
    with zipfile.ZipFile(BytesIO(data)) as z:
        entries=z.infolist();names=[i.filename for i in entries]
        if len(entries)>250 or len(names)!=len(set(names)) or sum(i.file_size for i in entries)>250*1024*1024:raise ValueError('ARCHIVE_BOUNDS')
        if apk_only:
            if 'AndroidManifest.xml' not in names:raise ValueError('APK_MANIFEST_REQUIRED')
            raw=data
        else:
            info=z.getinfo(package+'.apk')
            if info.file_size>100*1024*1024:raise ValueError('APK_BOUNDS')
            raw=z.read(info)
    apk=APK(raw,raw=True);code=int(apk.get_androidversion_code())
    if apk.get_package()!=package or build is not None and code!=build:raise ValueError('IDENTITY_MISMATCH')
    result={'package':package,'versionName':apk.get_androidversion_name(),'versionCode':code,'apkBytes':len(raw),'apkSha256':hashlib.sha256(raw).hexdigest(),'xapkBytes':len(data),'xapkSha256':hashlib.sha256(data).hexdigest(),'certificateSha256':sorted(c.sha256.hex() for c in apk.get_certificates()),'cryptographicApkSignatureVerified':False,'apkCodeExecuted':False,'sourceCategory':'public distribution for owner-requested interoperability'}
    base=folder/'base.apk'
    if not base.exists():m.save_private(raw,base)
    elif base.is_symlink() or hashlib.sha256(base.read_bytes()).hexdigest()!=result['apkSha256']:raise ValueError('BASE_MISMATCH')
    (folder/'identity.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('app',choices=PACKAGES);p.add_argument('private',type=Path);p.add_argument('--build',type=int);p.add_argument('--apk',action='store_true');a=p.parse_args();acquire(a.app,a.private,a.build,a.apk)
