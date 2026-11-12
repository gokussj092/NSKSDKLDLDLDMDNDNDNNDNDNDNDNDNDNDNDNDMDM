#!/usr/bin/env python3
"""Bounded, static inventory of the owner-supplied Litron Pro APKS."""
import argparse,hashlib,json,os,zipfile
from pathlib import Path
from androguard.core.apk import APK
from loguru import logger
logger.disable('androguard')
def prepare(source,out):
    source=Path(source);out=Path(out);out.mkdir(parents=True,exist_ok=True,mode=0o700);out.chmod(0o700)
    if source.stat().st_size>100*1024*1024:raise ValueError('APKS_BOUNDS')
    with zipfile.ZipFile(source) as z:
        entries=z.infolist();names=[i.filename for i in entries]
        if len(entries)>64 or len(names)!=len(set(names)) or sum(i.file_size for i in entries)>150*1024*1024:raise ValueError('ARCHIVE_BOUNDS')
        raw=z.read('base.apk')
        splits=[{'name':i.filename,'bytes':i.file_size,'sha256':hashlib.sha256(z.read(i)).hexdigest()} for i in entries]
    apk=APK(raw,raw=True)
    if apk.get_package()!='com.litron.udp':raise ValueError('UNEXPECTED_PACKAGE')
    result={'package':apk.get_package(),'versionName':apk.get_androidversion_name(),'versionCode':int(apk.get_androidversion_code()),
        'apksBytes':source.stat().st_size,'apksSha256':hashlib.sha256(source.read_bytes()).hexdigest(),
        'apkBytes':len(raw),'apkSha256':hashlib.sha256(raw).hexdigest(),'splits':splits,
        'certificateSha256':sorted(c.sha256.hex() for c in apk.get_certificates()),
        'cryptographicApkSignatureVerified':False,'apkCodeExecuted':False,'sourceCategory':'owner-provided APKS'}
    p=out/'base.apk'
    if p.exists():
        if p.is_symlink() or hashlib.sha256(p.read_bytes()).hexdigest()!=result['apkSha256']:raise ValueError('EXISTING_BASE_MISMATCH')
    else:
        with os.fdopen(os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb') as f:f.write(raw)
    (out/'identity.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('apks',type=Path);p.add_argument('private',type=Path);a=p.parse_args();prepare(a.apks,a.private)
