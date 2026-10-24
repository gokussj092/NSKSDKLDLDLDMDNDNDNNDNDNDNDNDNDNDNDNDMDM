#!/usr/bin/env python3
"""Verify whole private APNA catalog/profile JSON against JDK and worker."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'cloud/workers/python'))
from decoders.Python.apps.APNA_VPN import server_catalog_decoder as codec
from engine import decode_provider_catalog,decode_file,decode_text


def verify(path,profile=False):
    data=path.read_bytes()
    opened=codec.decode_profile_bytes(data) if profile else codec.decode_json_bytes(data)
    oracle=ROOT/'tests/golden/apna_oracle.java'
    independent=subprocess.run(['java',str(oracle),'profile' if profile else 'catalog',str(path)],capture_output=True,check=True,timeout=45).stdout
    assert opened==independent,'Complete JDK plaintext differs'
    actual=json.loads(opened)
    result=decode_file('apnavpn',data) if profile else decode_provider_catalog('apna-vpn',data)
    assert result['structuredJson']==actual and not result['isPartial'],'Isolated worker differs'
    if profile:
        token=data.decode().strip()
        if not token.startswith(codec.PROFILE_PREFIX):token=codec.PROFILE_PREFIX+token
        assert decode_text(token)['structuredJson']==actual,'Text worker differs'
        return {'profile':True,'jdkEqual':True,'workerEqual':True,'textWorkerEqual':True}
    summary=codec.summary(opened)
    return {'version':summary['version'],'servers':summary['serverCounts'],
        'payloads':summary['payloadCount'],'bytes':summary['plaintextBytes'],'jdkEqual':True,'workerEqual':True}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--file',action='store_true')
    parser.add_argument('paths',nargs='+',type=Path);args=parser.parse_args()
    for path in args.paths:print(json.dumps(verify(path,args.file)))


if __name__=='__main__':main()
