#!/usr/bin/env python3
"""Compare complete private ANY documents with JDK and isolated worker."""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'cloud/workers/python'))
from decoders.Python.apps.ANY_VPN import codec
from engine import decode_provider_catalog,decode_file


def verify(path,profile=False):
    source=codec.bounded(path.read_bytes())
    actual=(codec.decode_profile if profile else codec.decode_catalog)(source)
    oracle=ROOT/'tests/golden/any_vpn_oracle.java'
    reference=json.loads(subprocess.run(['java',str(oracle),'outer',str(path)],
        check=True,capture_output=True,timeout=45).stdout)
    targets=[]
    if profile:
        for name,fields in [('server',codec.SERVER_FIELDS),('network',codec.NETWORK_FIELDS)]:
            if name not in reference or reference[name]=='':continue
            if isinstance(reference[name],str):reference[name]=json.loads(reference[name])
            targets.append((reference[name],fields))
    else:
        targets.append((reference,codec.METADATA_FIELDS))
        targets.extend((row,fields) for name,fields in [('Servers',codec.SERVER_FIELDS),('Networks',codec.NETWORK_FIELDS)] for row in reference[name])
    pending=[(obj,key,obj[key]) for obj,fields in targets for key in sorted(fields) if key in obj]
    if pending:
        result=subprocess.run(['java',str(oracle),'fields'],input=('\n'.join(v for _,_,v in pending)+'\n').encode(),
            check=True,capture_output=True,timeout=45)
        lines=result.stdout.decode().splitlines()
        assert len(lines)==len(pending),'JDK omitted fields'
        for (obj,key,_),line in zip(pending,lines):obj[key]=base64.b64decode(line,validate=True).decode()
    assert actual==reference,'Complete JDK JSON differs'
    result=decode_file('dtk',source) if profile else decode_provider_catalog('any-vpn',source)
    assert result['structuredJson']==actual and not result['isPartial'],'Complete worker JSON differs'
    return {'profile':profile,'version':actual.get('Version'),'servers':len(actual.get('Servers',[])),
        'networks':len(actual.get('Networks',[])),'fields':len(pending),'jdkEqual':True,'workerEqual':True}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--file',action='store_true')
    parser.add_argument('paths',type=Path,nargs='+');args=parser.parse_args()
    for path in args.paths:print(json.dumps(verify(path,args.file)))


if __name__=='__main__':main()
