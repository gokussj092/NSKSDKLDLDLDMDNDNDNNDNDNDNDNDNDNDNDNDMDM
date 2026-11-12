#!/usr/bin/env python3
"""Reproduce bounded native/asset extraction; do not execute or load APK code."""
import argparse,hashlib,json,sys,zipfile
from io import BytesIO
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from mirror_archive import apk_members
def extract(kind,folder):
    folder=Path(folder);result={}
    if kind=='open':
        with zipfile.ZipFile(folder/'distribution.xapk') as z:
            split=z.read('config.arm64_v8a.apk')
        jobs=[(split,'lib/arm64-v8a/libopentunnel.so','libopentunnel.so','5f5449eb72551bdf6a285d09322c8290554068f49d9f6682bab6609664c40ba1')]
    else:
        members=apk_members((folder/'distribution.zip').read_bytes())
        split=next(raw for name,raw in members if name=='config.arm64_v8a.apk')
        jobs=[(split,'lib/arm64-v8a/libgojni.so','libgojni.so','f7a1be6ef0cf4939e480cb772dbbaf49e68246a4ca205258e052e4215f015260'),(split,'lib/arm64-v8a/libuz.so','libuz.so','b2dd7d82ff8fd0dd596f68f8c87a3400b49eab2237232af38f4efc2e109e28a1'),((folder/'base.apk').read_bytes(),'assets/configfile.json','embedded.bin','8fb653a733e2eb04f7098926a3e028d0439b990d40fcef79c14012915c938665')]
    for archive,member,name,expected in jobs:
        with zipfile.ZipFile(BytesIO(archive)) as z:
            if z.getinfo(member).file_size>64*1024*1024:raise ValueError('MEMBER_LIMIT')
            raw=z.read(member)
        sha=hashlib.sha256(raw).hexdigest()
        if sha!=expected:raise ValueError('MEMBER_MISMATCH')
        target=folder/name
        if target.exists() and target.read_bytes()!=raw:raise ValueError('OUTPUT_MISMATCH')
        target.write_bytes(raw);target.chmod(0o600);result[member]={'bytes':len(raw),'sha256':sha}
    print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('kind',choices=['open','mdproxy']);p.add_argument('private',type=Path);a=p.parse_args();extract(a.kind,a.private)
