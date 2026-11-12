#!/usr/bin/env python3
"""Acquire only com.fleet.vpn (LITRON VPN), never com.litron.udp (Pro)."""
import argparse,hashlib,importlib.util,json,os,zipfile
from io import BytesIO
from pathlib import Path
from androguard.core.apk import APK
from loguru import logger
logger.disable('androguard')
ROOT=Path(__file__).resolve().parents[4]
PACKAGE='com.fleet.vpn'
def acquire(out,build=None):
    path=ROOT/'analysis/com.tunneldoom.http/432/tools/acquire.py'
    s=importlib.util.spec_from_file_location('vetted_acquirer',path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
    query='version=latest' if build is None else 'versionCode='+str(build)
    m.SOURCE='https://d.apkpure.net/b/XAPK/'+PACKAGE+'?'+query
    out=Path(out);out.mkdir(parents=True,exist_ok=True,mode=0o700);out.chmod(0o700)
    p=out/'distribution.xapk'
    if p.is_symlink():raise ValueError('UNSAFE_INPUT')
    data=p.read_bytes() if p.exists() else m.fetch_xapk()
    if len(data)>m.MAX_BYTES:raise ValueError('XAPK_BOUNDS')
    if not p.exists():m.save_private(data,p)
    with zipfile.ZipFile(BytesIO(data)) as z:
        info=z.getinfo(PACKAGE+'.apk')
        if info.file_size>100*1024*1024:raise ValueError('APK_BOUNDS')
        raw=z.read(info)
    apk=APK(raw,raw=True);code=int(apk.get_androidversion_code())
    if apk.get_package()!=PACKAGE or build is not None and code!=build:raise ValueError('IDENTITY_MISMATCH')
    result={'package':PACKAGE,'versionName':apk.get_androidversion_name(),'versionCode':code,'apkBytes':len(raw),
        'apkSha256':hashlib.sha256(raw).hexdigest(),'xapkBytes':len(data),'xapkSha256':hashlib.sha256(data).hexdigest(),
        'certificateSha256':sorted(c.sha256.hex() for c in apk.get_certificates()),'cryptographicApkSignatureVerified':False,'apkCodeExecuted':False}
    base=out/'base.apk'
    if not base.exists():m.save_private(raw,base)
    elif base.is_symlink() or hashlib.sha256(base.read_bytes()).hexdigest()!=result['apkSha256']:raise ValueError('BASE_MISMATCH')
    (out/'identity.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);p.add_argument('--build',type=int);a=p.parse_args();acquire(a.private,a.build)
