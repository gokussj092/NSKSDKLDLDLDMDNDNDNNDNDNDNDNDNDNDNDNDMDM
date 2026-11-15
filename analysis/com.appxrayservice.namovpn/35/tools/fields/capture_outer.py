#!/usr/bin/env python3
"""Preserve the initial read-only probe (originally executed inline).

Capture uses the original fixed updater and Java envelope oracle. Real values
stay in the chosen private directory, mode 0600. Only shapes/hashes are public.
"""
import argparse,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[5];sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from decoders.Python.apps.NAMO_VPN.server_catalog_decoder import download
from recover import oracle,LIB_SHA
from scripts.apk_analysis.elf_inspect import ElfImage

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args()
    a.private.mkdir(parents=True,exist_ok=True,mode=0o700)
    lib=a.private/'unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libapi-namo.so'
    assert hashlib.sha256(lib.read_bytes()).hexdigest()==LIB_SHA
    key=ElfImage(lib).cstring(0x541).encode()
    data=download();outer=oracle('D',key,[data])[0];doc=json.loads(outer)
    for name,value in [('remote.enc',data),('outer.json',outer)]:
        path=a.private/name;path.touch(mode=0o600,exist_ok=True);path.chmod(0o600);path.write_bytes(value)
    print(json.dumps({'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
        'version':doc['Version'],'keys':list(doc),
        'counts':{g:len(doc[g]) for g in ['Servers','Networks']}}))
if __name__=='__main__':main()
