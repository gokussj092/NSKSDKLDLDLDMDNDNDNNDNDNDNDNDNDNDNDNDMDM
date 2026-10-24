#!/usr/bin/env python3
"""Extract the known AM-63 LIAPP native first stage offline; not a DEX unpacker."""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path

WRAPPER_SHA256='f09f2ab5e12d41836ed4ddd25022bfac7271432710462312cca7790accfaeb29'
CORE_SHA256='fe2ee74275a21be8b6ff728d00761db8676fb729af2de4e455b672f500c7e5e6'
MARKER=bytes.fromhex('0806090107020301')
MAX_BYTES=2*1024*1024


def unpack(data: bytes) -> bytes:
    if not isinstance(data,bytes) or len(data)>MAX_BYTES or hashlib.sha256(data).hexdigest()!=WRAPPER_SHA256:
        raise ValueError('Unsupported LIAPP wrapper build')
    offset=data.find(MARKER,0x2800)
    if offset!=0x78b8 or data.find(MARKER,offset+1)!=-1:raise ValueError('Unexpected wrapper layout')
    # Constructor 0x32b4..0x3344 finds this marker and restores ELF magic.
    result=b'\x7fELF'+data[offset+12:]
    if hashlib.sha256(result).hexdigest()!=CORE_SHA256:raise ValueError('Unexpected native core')
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('wrapper',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    if a.output.exists():p.error('Output already exists')
    with a.wrapper.open('rb') as stream:raw=stream.read(MAX_BYTES+1)
    result=unpack(raw);a.output.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with a.output.open('xb') as stream:stream.write(result)
    a.output.chmod(0o600)
    print(json.dumps({'nativeBytes':len(result),'nativeSha256':CORE_SHA256,'dexRecovered':False,'catalogDecoded':False}))

if __name__=='__main__':main()
