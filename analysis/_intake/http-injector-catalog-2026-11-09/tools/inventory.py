#!/usr/bin/env python3
"""Static catalog-source inventory, without keys, tokens, hooks or APK execution."""
import argparse,hashlib,json,re,zipfile
from io import BytesIO
from pathlib import Path
from urllib.parse import urlsplit,parse_qsl
URL=re.compile(rb'https?://[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%+-]{5,1500}')
NATIVE={'libevozi.so','libdexjniehi.so','libdf.so','libdatajar.so','libDexHelper.so','libevozi_sentinel.so','libtunnelcore.so'}
BASE_SHA256='5dc3976ad0d90c14b79f5848109296998f930c9d36be88fba9115c078f60dfe3'
BUNDLE_SHA256='03737e8e7985fdf8227f393d570316f65ea075863007fc2b002ad8e3ff97b698'
def describe(raw):
    magic='ELF' if raw.startswith(b'\x7fELF') else 'ZIP' if raw.startswith(b'PK\x03\x04') else 'DEX' if raw.startswith(b'dex\n') else 'OTHER'
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'container':magic}
def urls(raw,source):
    rows=[]
    for match in URL.finditer(raw):
        try:u=urlsplit(match[0].decode('ascii'));host=u.hostname
        except ValueError:continue
        if not host or not any(host==d or host.endswith('.'+d) for d in ('evozi.com','evozi.net','httpinjector.com','ehi.tools')):continue
        path=re.sub(r'/[A-Za-z0-9_=-]{33,}(?=/|$)','/[opaque-segment]',u.path)
        rows.append({'source':source,'scheme':u.scheme,'host':host,'path':path,
          'queryNames':sorted(set(k for k,v in parse_qsl(u.query,keep_blank_values=True))),
          'hadUserInfo':bool(u.username or u.password)})
    return rows
def inventory(private):
    raw=(private/'base.apk').read_bytes()
    bundle_raw=(private/'distribution.bin').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=BASE_SHA256 or hashlib.sha256(bundle_raw).hexdigest()!=BUNDLE_SHA256:
        raise ValueError('BUILD_HASH_MISMATCH')
    inputs=private/'inputs';inputs.mkdir(parents=True,exist_ok=True,mode=0o700)
    result={'apk':describe(raw),'assets':{},'native':{},'sourceCandidates':[],
      'apkCodeExecuted':False,'authenticationMaterialCollected':False}
    with zipfile.ZipFile(BytesIO(raw)) as z:
        for name in ('classes.dex','assets/info.y','res/raw/about'):
            data=z.read(name);result['assets'][name]=describe(data);result['sourceCandidates']+=urls(data,name)
            if name!='classes.dex':
                target=inputs/Path(name).name;target.write_bytes(data);target.chmod(0o600)
    with zipfile.ZipFile(BytesIO(bundle_raw)) as bundle:
        for member in bundle.namelist():
            if not member.endswith('.apk'):continue
            entry=bundle.getinfo(member)
            if entry.file_size>125*1024*1024:raise ValueError('SPLIT_SIZE')
            with zipfile.ZipFile(BytesIO(bundle.read(member))) as z:
                for info in z.infolist():
                    name=Path(info.filename).name
                    if not info.filename.startswith('lib/') or name not in NATIVE:continue
                    if info.file_size>64*1024*1024:raise ValueError('NATIVE_SIZE')
                    data=z.read(info);result['native'][name]=describe(data)
                    result['sourceCandidates']+=urls(data,name)
                    path=inputs/name;path.write_bytes(data);path.chmod(0o600)
    result['sourceCandidates']=list({json.dumps(x,sort_keys=True):x for x in result['sourceCandidates']}.values())
    target=private/'catalog-inventory.json';target.write_text(json.dumps(result,indent=2)+'\n');target.chmod(0o600)
    print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();inventory(a.private)
