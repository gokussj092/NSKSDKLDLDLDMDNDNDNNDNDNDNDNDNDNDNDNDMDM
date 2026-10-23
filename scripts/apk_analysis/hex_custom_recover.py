#!/usr/bin/env python3
"""Recover Hex Custom 10.6.1 analysis inputs, not an exported-file decoder.

Offline and build-pinned: split the signed KVS1 container and recover the
CustomServerShare JNI map from the original XOR string pool. VM bytecode stays
protected. No JNI startup, protection bypass, provider requests or APK patching.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct

SO_SHA256='17b2261afd80aaf49ae9b13c9202b080bc314216d79b072b8b6ebb3599ff052b'
DAT_SHA256='189950128de62063947587dc542c2708fe3a20f7f449477b9e8b76fae42641e8'
MAX_BYTES=64*1024*1024
POOL_ADDRESS=0x429c38
POOL_SIZE=0x856b8
POOL_KEY_ADDRESS=0x2d8e8


def unique(pairs):
    out={}
    for key,value in pairs:
        if key in out:raise ValueError('Duplicate manifest field')
        out[key]=value
    return out


def parse_container(data):
    if not isinstance(data,bytes) or not 84<=len(data)<=MAX_BYTES:raise ValueError('Invalid container size')
    magic,version,manifest_size,table_size,payload_size=struct.unpack('<4s4I',data[:20])
    if (magic!=b'KVS1' or version!=1 or not 1<=manifest_size<=65536 or
        not table_size or table_size%16 or table_size>512*16 or not payload_size or
        20+manifest_size+table_size+payload_size+64!=len(data)):
        raise ValueError('Invalid KVS1 framing')
    end=20+manifest_size
    manifest=json.loads(data[20:end].decode('utf-8'),object_pairs_hook=unique)
    if not isinstance(manifest,dict) or manifest.get('format')!=1 or not isinstance(manifest.get('files'),list):
        raise ValueError('Invalid KVS1 manifest')
    payload=data[end+table_size:-64];packages=[];ids=set()
    for pos in range(end,end+table_size,16):
        ident,offset,length=struct.unpack('<IIQ',data[pos:pos+16])
        if ident in ids or not length or offset+length>payload_size:raise ValueError('Invalid package range')
        ids.add(ident)
        packages.append({'id':ident,'offset':offset,'bytes':length,'data':payload[offset:offset+length]})
    cursor=0
    for p in sorted(packages,key=lambda p:p['offset']):
        if p['offset']!=cursor:raise ValueError('Overlapping or incomplete package ranges')
        cursor+=p['bytes']
    if cursor!=payload_size:raise ValueError('Incomplete payload')
    return manifest,packages,data[-64:]


def recover_methods(library):
    from elf_inspect import ElfImage
    if hashlib.sha256(Path(library).read_bytes()).hexdigest()!=SO_SHA256:raise ValueError('Unknown native build')
    image=ElfImage(library)
    key=image.read(POOL_KEY_ADDRESS,8)
    encoded=image.read(POOL_ADDRESS,POOL_SIZE)
    pool=bytes(v^key[i%8] for i,v in enumerate(encoded))
    relative={r['r_offset']:r['r_addend'] for r in image.relocations if r['r_info_type']==1027}
    def u32(address):return struct.unpack('<I',image.read(address,4))[0]
    def text(index):
        offset=u32(0x772e4+index*4)
        if offset>=len(pool):raise ValueError('Invalid string offset')
        return pool[offset:pool.index(0,offset)].decode('utf-8')
    class_id,start,count=struct.unpack('<3I',image.read(0x75844+226*12,12))
    class_name=text(u32(0x86298+class_id*4))
    if class_name!='com/hexapplications/hexvpn/ui/servers/CustomServerShare' or count!=10:
        raise ValueError('Unexpected class mapping')
    methods=[]
    for index in range(start,start+count):
        address=0x390420+index*16
        name,signature,target=struct.unpack('<IIQ',image.read(address,16))
        methods.append({'name':text(name),'signature':text(signature),'address':hex(relative.get(address+8,target))})
    return image,pool,methods


def verify_pool(library,pool):
    # Execute only the tiny original XOR loop. No JNI_OnLoad, VM, OS or gates.
    from arm64_function import Arm64Function
    machine=Arm64Function(library)
    machine.call(0x21670c,limit=12_000_000)
    if machine.read(POOL_ADDRESS,POOL_SIZE)!=pool:raise ValueError('Native XOR pool differs')


def write_private(path,data):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as out:out.write(data)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('library',type=Path);p.add_argument('container',type=Path);p.add_argument('output',type=Path)
    p.add_argument('--verify-xor',action='store_true',help='Compare all pool bytes to the original isolated ARM64 XOR loop')
    a=p.parse_args()
    if a.output.exists():p.error('Output must not exist')
    with a.container.open('rb') as f:data=f.read(MAX_BYTES+1)
    if hashlib.sha256(data).hexdigest()!=DAT_SHA256:p.error('Unknown container build')
    manifest,packages,signature=parse_container(data)
    image,pool,methods=recover_methods(a.library)
    if a.verify_xor:verify_pool(a.library,pool)
    a.output.mkdir(parents=True,mode=0o700)
    report={'status':'analysis_only_decoder_pending','signatureBytes':len(signature),'signatureVerified':False,
            'nativePoolEqual':a.verify_xor,'poolBytes':len(pool),'methods':methods,'packages':[]}
    for item in packages:
        raw=item.pop('data');name=f"package-{item['id']}.protected.bin"
        write_private(a.output/name,raw)
        report['packages'].append({**item,'file':name,'sha256':hashlib.sha256(raw).hexdigest()})
    write_private(a.output/'pool7.private.bin',pool)
    write_private(a.output/'manifest.private.json',json.dumps(manifest,indent=2).encode())
    write_private(a.output/'analysis.private.json',json.dumps(report,indent=2).encode())
    print(json.dumps({'status':report['status'],'packages':len(packages),'methods':len(methods),
                      'poolBytes':len(pool),'nativePoolEqual':report['nativePoolEqual']}))


if __name__=='__main__':main()
