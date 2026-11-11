#!/usr/bin/env python3
"""Two-slot, atomic public APK publisher. Never stores signing keys.

Current always points to a verified slot; the other slot is the single backup.
A failed build or verification does not touch the current public release.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from datetime import datetime, timezone

CHANNELS = ('online','offline')
SHA = re.compile(r'^[0-9a-f]{64}$')
SOURCE = re.compile(r'^[0-9a-f]{40}$')
VERSION = re.compile(r'^[0-9]+\.[0-9]+\.[0-9]+$')
TARGETS = {'a':'slots/a', 'b':'slots/b'}

def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as reader:
        for data in iter(lambda:reader.read(1024*1024),b''):h.update(data)
    return h.hexdigest()

def load_slot(folder):
    try:
        meta=json.loads((folder/'release.json').read_text())
        file=folder/'release.apk'
        if (meta.get('packageName') != ('com.ghostdeveloper.spdecode.offline' if meta.get('channel')=='offline' else 'com.ghostdeveloper.spdecode') or
            meta.get('channel') not in CHANNELS or
            not VERSION.fullmatch(meta.get('version','')) or
            not SOURCE.fullmatch(meta.get('sourceCommit','')) or
            not SHA.fullmatch(meta.get('sha256','')) or
            not SHA.fullmatch(meta.get('signerCertSha256','')) or
            type(meta.get('versionCode')) is not int or
            meta['versionCode']<1 or
            not file.is_file() or file.stat().st_size<100000 or
            file.stat().st_size!=meta.get('bytes') or
            digest(file)!=meta['sha256']):return None
        return meta
    except (OSError,ValueError,TypeError,KeyError,AttributeError):return None

def active_slot(folder):
    pointer=folder/'current'
    if not pointer.is_symlink():return None
    destination=os.readlink(pointer)
    if destination not in TARGETS.values():raise RuntimeError('INVALID_RELEASE_POINTER')
    return next(k for k,v in TARGETS.items() if v==destination)

def point(folder,target):
    temp=folder/'.current.next'
    if temp.exists() or temp.is_symlink():temp.unlink()
    os.symlink(TARGETS[target],temp)
    os.replace(temp,folder/'current')

def publish(root,channel,apk,version,code,source,signer):
    if channel not in CHANNELS:raise ValueError('BAD_CHANNEL')
    if not VERSION.fullmatch(version):raise ValueError('BAD_VERSION')
    if not SOURCE.fullmatch(source):raise ValueError('BAD_SOURCE')
    if not SHA.fullmatch(signer):raise ValueError('BAD_SIGNER')
    if code<1:raise ValueError('BAD_VERSION_CODE')
    apk=Path(apk);root=Path(root)
    root.mkdir(parents=True,exist_ok=True)
    root.chmod(0o755)
    base=root/channel
    if not apk.is_file() or apk.stat().st_size<100000:raise RuntimeError('INVALID_APK')
    base.mkdir(parents=True,exist_ok=True)
    (base/'slots').mkdir(exist_ok=True)
    active=active_slot(base)
    current=load_slot(base/TARGETS[active]) if active else None
    if active and (not current or current.get('channel')!=channel):raise RuntimeError('CORRUPT_ACTIVE_RELEASE')
    if current and (code<=current['versionCode'] or signer!=current['signerCertSha256']):
        raise RuntimeError('VERSION_OR_SIGNER_MISMATCH')
    target='b' if active=='a' else 'a'
    destination=base/TARGETS[target]
    staging=Path(tempfile.mkdtemp(prefix='.candidate-',dir=base/'slots'))
    try:
        staged=staging/'release.apk'
        shutil.copyfile(apk,staged)
        os.chmod(staged,0o644)
        meta={
          'channel':channel,'packageName':('com.ghostdeveloper.spdecode.offline' if channel=='offline' else 'com.ghostdeveloper.spdecode'),
          'version':version,'versionCode':code,
          'sourceCommit':source,'signerCertSha256':signer,
          'sha256':digest(staged),'bytes':staged.stat().st_size,
          'publishedAt':datetime.now(timezone.utc).isoformat(timespec='seconds')
        }
        (staging/'release.json').write_text(json.dumps(meta,sort_keys=True)+'\n')
        os.chmod(staging/'release.json',0o644)
        if not load_slot(staging):raise RuntimeError('CANDIDATE_VERIFY_FAILED')
        if destination.exists():shutil.rmtree(destination)
        os.rename(staging,destination)
        point(base,target)
        os.chmod(base,0o755)
        os.chmod(base/'slots',0o755)
        os.chmod(destination,0o755)
        return meta
    finally:
        if staging.exists():shutil.rmtree(staging)

def rollback(root,channel):
    if channel not in CHANNELS:raise ValueError('BAD_CHANNEL')
    base=Path(root)/channel
    active=active_slot(base)
    if active is None:raise RuntimeError('NO_PUBLIC_RELEASE')
    previous='b' if active=='a' else 'a'
    meta=load_slot(base/TARGETS[previous])
    if not meta or meta.get('channel')!=channel:raise RuntimeError('NO_VERIFIED_BACKUP')
    point(base,previous)
    return meta

def status(root,channel):
    if channel not in CHANNELS:raise ValueError('BAD_CHANNEL')
    base=Path(root)/channel
    active=active_slot(base)
    inactive='b' if active=='a' else 'a'
    return {'current':load_slot(base/TARGETS[active]) if active else None,
            'previous':load_slot(base/TARGETS[inactive]) if active else None}

def main():
    p=argparse.ArgumentParser()
    p.add_argument('action',choices=['publish','rollback','status'])
    p.add_argument('channel',choices=CHANNELS)
    p.add_argument('--root',default='/opt/spdecode/public-apks')
    p.add_argument('--apk')
    p.add_argument('--version')
    p.add_argument('--code',type=int)
    p.add_argument('--source')
    p.add_argument('--signer')
    args=p.parse_args()
    if args.action=='publish':
        if not all([args.apk,args.version,args.code,args.source,args.signer]):p.error('Missing signed build metadata')
        result=publish(args.root,args.channel,args.apk,args.version,args.code,args.source,args.signer)
    elif args.action=='rollback':result=rollback(args.root,args.channel)
    else:result=status(args.root,args.channel)
    print(json.dumps(result,sort_keys=True))
if __name__=='__main__':
    try:main()
    except (ValueError,RuntimeError,OSError) as exc:
        print('PUBLIC_APK_ERROR: '+str(exc),file=sys.stderr)
        sys.exit(1)
