#!/usr/bin/env python3
"""Bounded static identity of the owner's Play APKS; no application execution."""
import argparse,hashlib,json,os,zipfile
from pathlib import Path
from androguard.core.apk import APK
from loguru import logger
logger.disable('androguard')
def prepare(source,out):
    source=Path(source);out=Path(out);out.mkdir(parents=True,exist_ok=True,mode=0o700);out.chmod(0o700)
    if source.stat().st_size>100*1024*1024:raise ValueError('APKS_BOUNDS')
    with zipfile.ZipFile(source) as z:
        entries=z.infolist();names=[x.filename for x in entries]
        if len(set(names))!=len(names) or len(entries)>64 or sum(x.file_size for x in entries)>150*1024*1024:raise ValueError('ARCHIVE_BOUNDS')
        if 'base.apk' not in names:raise ValueError('BASE_REQUIRED')
        item=z.getinfo('base.apk')
        if item.file_size>100*1024*1024:raise ValueError('BASE_BOUNDS')
        raw=z.read(item)
        split_hashes=[{'name':i.filename,'bytes':i.file_size,'sha256':hashlib.sha256(z.read(i)).hexdigest()} for i in entries]
    apk=APK(raw,raw=True)
    if apk.get_package()!='net.catnet.vpn':raise ValueError('PACKAGE_MISMATCH')
    result={'package':apk.get_package(),'versionName':apk.get_androidversion_name(),'versionCode':int(apk.get_androidversion_code()),
        'apksBytes':source.stat().st_size,'apksSha256':hashlib.sha256(source.read_bytes()).hexdigest(),
        'apkBytes':len(raw),'apkSha256':hashlib.sha256(raw).hexdigest(),'splits':split_hashes,
        'certificateSha256':sorted(c.sha256.hex() for c in apk.get_certificates()),
        'sourceCategory':'owner-provided Play export; filename is not authoritative identity',
        'cryptographicApkSignatureVerified':False,'apkCodeExecuted':False}
    base=out/'base.apk'
    if base.exists():
        if base.is_symlink() or hashlib.sha256(base.read_bytes()).hexdigest()!=result['apkSha256']:raise ValueError('EXISTING_BASE_MISMATCH')
    else:
        with os.fdopen(os.open(base,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb') as f:f.write(raw)
    (out/'identity.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('apks',type=Path);p.add_argument('private',type=Path);a=p.parse_args();prepare(a.apks,a.private)
