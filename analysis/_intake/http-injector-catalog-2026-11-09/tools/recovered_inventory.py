#!/usr/bin/env python3
"""Validate known native container layouts and inspect public source URLs only.

Container decoding is static data parsing; no native APK library is loaded.
No service-authentication key or request-signing value is collected/reused.
"""
import argparse,importlib.util,json
from pathlib import Path
from inventory import describe,urls
SOURCE=Path(__file__).with_name('historical')/'httpinjector_650_unpack_native.py'
def inspect(private):
    spec=importlib.util.spec_from_file_location('historical_unpack',SOURCE);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    out=private/'unpacked';out.mkdir(exist_ok=True,mode=0o700)
    records=[];candidates=[]
    for name in ('libevozi.so','libevozi_sentinel.so','libdf.so','libtunnelcore.so'):
        raw=(private/'inputs'/name).read_bytes();result={'name':name,'recovered':False,'validations':[]}
        for layout in ('libdexjniehi.so','libDexHelper.so'):
            try:
                clear=m.unpack(layout,raw)
                target=out/(name+'.unpacked');target.write_bytes(clear);target.chmod(0o600)
                result.update(recovered=True,layoutFrom=layout,**describe(clear));break
            except (ValueError,IndexError) as e:result['validations'].append(type(e).__name__)
        records.append(result)
    for f in sorted(out.glob('*.unpacked')):candidates+=urls(f.read_bytes(),f.name)
    result={'nativeContainers':records,'sourceCandidates':candidates,'nativeApkCodeExecuted':False,
      'authenticationMaterialCollected':False,'catalogVerified':False}
    target=private/'recovered-inventory.json';target.write_text(json.dumps(result,indent=2)+'\n');target.chmod(0o600);print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();inspect(a.private)
