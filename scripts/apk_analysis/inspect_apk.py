#!/usr/bin/env python3
"""Inspect APK/APKS offline; extract DEX, original PNG and explicit assets/libs."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path,PurePosixPath
import re
import zipfile

MAX_ENTRY=300*1024*1024
MAX_TOTAL=600*1024*1024


def safe_read(z: zipfile.ZipFile,name: str) -> bytes:
    if z.namelist().count(name)!=1:raise ValueError('Missing or duplicate ZIP entry')
    info=z.getinfo(name)
    if info.file_size>MAX_ENTRY:raise ValueError('ZIP entry exceeds limit')
    with z.open(info) as stream:data=stream.read(MAX_ENTRY+1)
    if len(data)>MAX_ENTRY:raise ValueError('ZIP entry exceeds limit')
    return data


def write(path: Path,data: bytes):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    path.write_bytes(data);path.chmod(0o600)


def relative(name: str) -> PurePosixPath:
    p=PurePosixPath(name)
    if p.is_absolute() or '..' in p.parts or '\\' in name:raise ValueError('Unsafe entry name')
    return p


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('input',type=Path);p.add_argument('output',type=Path)
    p.add_argument('--asset',action='append',default=[],help='Exact path relative to assets/')
    p.add_argument('--resource',action='append',default=[],help='Exact base-APK path under res/, e.g. res/raw/noobdev.js')
    p.add_argument('--native',action='append',default=[],help='Library basename, e.g. libputils.so')
    p.add_argument('--abi',default='arm64-v8a')
    a=p.parse_args();source=a.input.resolve();out=a.output.resolve()
    if source==out or out in source.parents:p.error('Output must not contain the input')
    if out.exists() and any(out.iterdir()):p.error('Output directory must be empty')
    out.mkdir(parents=True,exist_ok=True,mode=0o700)
    apk_paths=[]
    if source.suffix.lower()=='.apk':apk_paths=[source]
    else:
        with zipfile.ZipFile(source) as z:
            names=[n for n in z.namelist() if '/' not in n and n.endswith('.apk')]
            if not names or sum(z.getinfo(n).file_size for n in names)>MAX_TOTAL:raise ValueError('Invalid or excessive APK bundle')
            for n in names:
                target=out/'apks'/relative(n);write(target,safe_read(z,n));apk_paths.append(target)
    bases=[x for x in apk_paths if x.name=='base.apk']
    base=bases[0] if len(bases)==1 else (apk_paths[0] if len(apk_paths)==1 else None)
    if base is None:raise ValueError('Cannot identify base APK')
    from loguru import logger
    logger.remove()
    from androguard.core.apk import APK
    app=APK(str(base));icon=app.get_app_icon();entries=[]
    with zipfile.ZipFile(base) as z:
        for n in z.namelist():
            if re.fullmatch(r'classes(?:[2-9][0-9]*|1[0-9]+)?\.dex',n):
                b=safe_read(z,n);write(out/'dex'/n,b);entries.append({'path':n,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
        if icon and icon.lower().endswith('.png'):
            b=safe_read(z,icon);write(out/'icon.png',b)
            from PIL import Image
            import io
            width,height=Image.open(io.BytesIO(b)).size
            entries.append({'path':icon,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'width':width,'height':height})
        for asset in a.asset:
            name='assets/'+str(relative(asset));b=safe_read(z,name);write(out/'assets'/relative(asset),b)
        for resource in a.resource:
            name=relative(resource)
            if not name.parts or name.parts[0]!='res':raise ValueError('Expected a res/ resource path')
            b=safe_read(z,str(name));write(out/'resources'/name,b)
            entries.append({'path':str(name),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
    for lib in a.native:
        if relative(lib).name!=lib:raise ValueError('Expected library basename')
        name='lib/'+str(relative(a.abi))+'/'+lib;found=0
        for apk in apk_paths:
            with zipfile.ZipFile(apk) as z:
                if name in z.namelist():write(out/'native'/apk.stem/lib,safe_read(z,name));found+=1
        if not found:raise ValueError('Requested native library absent')
    report={'package':app.get_package(),'name':app.get_app_name(),'version':app.get_androidversion_name(),
        'versionCode':app.get_androidversion_code(),'baseSha256':hashlib.sha256(base.read_bytes()).hexdigest(),'entries':entries}
    write(out/'metadata.json',(json.dumps(report,ensure_ascii=False,indent=2)+'\n').encode())
    print(json.dumps({'package':report['package'],'version':report['version'],'extractedEntries':len(entries)}))

if __name__=='__main__':main()
