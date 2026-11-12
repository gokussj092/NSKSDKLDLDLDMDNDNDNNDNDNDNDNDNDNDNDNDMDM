#!/usr/bin/env python3
"""Static HMAC usage inventory only: no key values, hooks, connections or APK execution.

Counts of algorithms/APIs cannot establish service authentication. In particular,
file key derivation, catalog integrity and transport MACs are distinct purposes.
"""
import argparse,hashlib,importlib.util,json,re,zipfile
from io import BytesIO
from pathlib import Path
from androguard.core.apk import APK
from androguard.core.dex import DEX
from loguru import logger
logger.disable('androguard')
ROOT=Path(__file__).resolve().parents[4]
MAX_BYTES=125*1024*1024
ALGORITHMS=('HmacSHA1','HmacSHA224','HmacSHA256','HmacSHA384','HmacSHA512',
            'HmacMD5','HMAC-SHA1','HMAC-SHA256','HMAC-SHA512','PBKDF2WithHmacSHA1','PBKDF2WithHmacSHA256')
APIS={'macGetInstance':'Ljavax/crypto/Mac;->getInstance',
      'macInit':'Ljavax/crypto/Mac;->init','macDoFinal':'Ljavax/crypto/Mac;->doFinal',
      'keystoreGetInstance':'Ljava/security/KeyStore;->getInstance'}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def member(archive,name):
    info=archive.getinfo(name)
    if info.file_size>MAX_BYTES:raise ValueError('OVERSIZED_MEMBER')
    return archive.read(info)
def inventory(raw):
    with zipfile.ZipFile(BytesIO(raw)) as z:
        names=z.namelist()
        if len(names)>500 or len(names)!=len(set(names)):raise ValueError('ARCHIVE_BOUNDS')
        return names
def save(path,raw):
    if path.is_symlink():raise ValueError('UNSAFE_OUTPUT')
    path.write_bytes(raw);path.chmod(0o600)
def acquire(mode,directory,upload):
    directory.mkdir(parents=True,exist_ok=True,mode=0o700);directory.chmod(0o700)
    if mode=='from-upload':
        distribution=upload.read_bytes()
        with zipfile.ZipFile(BytesIO(distribution)) as z:
            apks=[n for n in inventory(distribution) if n.endswith('.apks')]
            if len(apks)!=1:raise ValueError('EXPECTED_SINGLE_APKS')
            bundle=member(z,apks[0])
        expected='com.evozi.injector';source='User-provided HTTP Injector_6.5.0.zip'
    else:
        spec=importlib.util.spec_from_file_location('approved_acquisition',ROOT/'analysis/com.tunneldoom.http/432/tools/acquire.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        source='https://d.apkpure.net/b/XAPK/netfree.mx.store?versionCode=123'
        module.SOURCE=source;distribution=module.fetch_xapk();bundle=distribution
        expected='netfree.mx.store'
    names=inventory(bundle)
    base=next((n for n in ('base.apk',expected+'.apk') if n in names),None)
    if not base:raise ValueError('BASE_APK_MISSING')
    with zipfile.ZipFile(BytesIO(bundle)) as z:raw=member(z,base)
    apk=APK(raw,raw=True)
    if apk.get_package()!=expected:raise ValueError('PACKAGE_MISMATCH')
    code=int(apk.get_androidversion_code());version=apk.get_androidversion_name()
    if mode=='download-speicers' and code!=123:raise ValueError('BUILD_MISMATCH')
    if mode=='from-upload' and version!='6.5.0':raise ValueError('VERSION_MISMATCH')
    identity=dict(package=expected,versionName=version,versionCode=code,source=source,
      distributionBytes=len(distribution),distributionSha256=sha(distribution),
      bundleSha256=sha(bundle),
      baseApkBytes=len(raw),baseApkSha256=sha(raw),certificateSha256=sorted(c.sha256.hex() for c in apk.get_certificates()),
      apkSignatureCryptographicallyVerified=False,apkCodeExecuted=False)
    save(directory/'distribution.bin',bundle);save(directory/'base.apk',raw)
    save(directory/'identity.json',(json.dumps(identity,indent=2)+'\n').encode())
    print(json.dumps(identity))
def scan(directory):
    identity=json.loads((directory/'identity.json').read_text());counts={k:0 for k in ALGORITHMS};calls={k:0 for k in APIS}
    if sha((directory/'base.apk').read_bytes())!=identity['baseApkSha256'] or sha((directory/'distribution.bin').read_bytes())!=identity['bundleSha256']:
        raise ValueError('IDENTITY_INPUT_MISMATCH')
    dex_count=0;method_count=0
    with zipfile.ZipFile(directory/'base.apk') as z:
        for name in z.namelist():
            if not re.fullmatch(r'classes\d*\.dex',name):continue
            dex_count+=1;dex=DEX(member(z,name))
            strings=list(dex.get_strings())
            for token in ALGORITHMS:counts[token]+=strings.count(token)
            for c in dex.get_classes():
                for m in c.get_methods():
                    method_count+=1
                    for instruction in m.get_instructions():
                        if not instruction.get_name().startswith('invoke-'):continue
                        reference=instruction.get_output()
                        for key,token in APIS.items():calls[key]+=int(token in reference)
    native={k:0 for k in ALGORITHMS};native_files=0
    with zipfile.ZipFile(directory/'distribution.bin') as bundle:
        for n in bundle.namelist():
            if not n.endswith('.apk'):continue
            with zipfile.ZipFile(BytesIO(member(bundle,n))) as split:
                for path in split.namelist():
                    if not path.startswith('lib/') or not path.endswith('.so'):continue
                    raw=member(split,path);native_files+=1
                    for token in ALGORITHMS:native[token]+=raw.count(token.encode())
    result=dict(schemaVersion=1,scanCompleted=True,package=identity['package'],versionCode=identity['versionCode'],baseApkSha256=identity['baseApkSha256'],dexFiles=dex_count,methodsVisited=method_count,
      algorithmStringCounts=counts,javaApiInvocationCounts=calls,nativeFiles=native_files,nativeAlgorithmMarkerCounts=native,
      vpnConnectionAuthenticationHmac='UNCONFIRMED',credentialMaterialExtracted=False,apkCodeExecuted=False,
      limitations=['Static counts do not establish execution, key provenance or purpose.',
       'No function inputs/outputs, key values, tokens or profiles are collected.',
       'No VPN/service connection, authentication bypass or dynamic hook was attempted.'])
    save(directory/'hmac-usage-summary.json',(json.dumps(result,indent=2)+'\n').encode());print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['from-upload','download-speicers','scan']);p.add_argument('private',type=Path)
    p.add_argument('--upload',type=Path);a=p.parse_args()
    if a.mode=='scan':scan(a.private)
    else:acquire(a.mode,a.private,a.upload)
