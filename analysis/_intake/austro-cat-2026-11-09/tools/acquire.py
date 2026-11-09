#!/usr/bin/env python3
"""Acquire either fixed public distribution and record its actual APK identity."""
import argparse,hashlib,importlib.util,json,zipfile
from io import BytesIO
from pathlib import Path
from androguard.core.apk import APK
from loguru import logger
logger.disable('androguard')
ROOT=Path(__file__).resolve().parents[4]
PACKAGES={'austro':'xyz.tekidoer.austroplus.vpn','catnet':'net.catnet.vpn'}
def acquire(app,out,build=None):
    package=PACKAGES[app]
    script=ROOT/'analysis/com.tunneldoom.http/432/tools/acquire.py'
    spec=importlib.util.spec_from_file_location('vetted_acquirer',script)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    query='version=latest' if build is None else 'versionCode='+str(build)
    module.SOURCE='https://d.apkpure.net/b/XAPK/'+package+'?'+query
    out=Path(out);out.mkdir(parents=True,exist_ok=True);out.chmod(0o700)
    target=out/'distribution.xapk'
    if target.is_symlink():raise ValueError('UNSAFE_INPUT')
    data=target.read_bytes() if target.exists() else module.fetch_xapk()
    if len(data)>module.MAX_BYTES:raise ValueError('DISTRIBUTION_BOUNDS')
    if not target.exists():module.save_private(data,target)
    with zipfile.ZipFile(BytesIO(data)) as archive:
        entry=archive.getinfo(package+'.apk')
        if entry.file_size>100*1024*1024:raise ValueError('BASE_BOUNDS')
        raw=archive.read(entry)
    apk=APK(raw,raw=True);code=int(apk.get_androidversion_code())
    if apk.get_package()!=package or build is not None and build!=code:raise ValueError('UNEXPECTED_IDENTITY')
    certificates=sorted(c.sha256.hex() for c in apk.get_certificates())
    result={'package':package,'versionName':apk.get_androidversion_name(),'versionCode':code,
        'xapkBytes':len(data),'xapkSha256':hashlib.sha256(data).hexdigest(),
        'apkBytes':len(raw),'apkSha256':hashlib.sha256(raw).hexdigest(),
        'certificateSha256':certificates,'cryptographicApkSignatureVerified':False,'apkCodeExecuted':False}
    base=out/'base.apk'
    if base.exists():
        if base.is_symlink() or hashlib.sha256(base.read_bytes()).hexdigest()!=result['apkSha256']:raise ValueError('BASE_MISMATCH')
    else:module.save_private(raw,base)
    (out/'identity.json').write_text(json.dumps(result,indent=2)+'\n');(out/'identity.json').chmod(0o600)
    return result
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('app',choices=PACKAGES);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--build',type=int);a=p.parse_args();print(json.dumps(acquire(a.app,a.out,a.build)))
