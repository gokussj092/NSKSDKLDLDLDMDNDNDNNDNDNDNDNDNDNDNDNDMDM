#!/usr/bin/env python3
"""Recover offline file-method evidence from the pinned HexVPN 1.7.3-Rev XAPK.

Private output only: original native files, authenticated VM packages, JNI map
and the file codec's constants. Does not execute application startup or the VM.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import zipfile
from Crypto.Cipher import ChaCha20_Poly1305

XAPK_SHA256 = 'b9ae5ea6d2e6b69974b6965db7f22d3f5361fcbf35dae8d754b3c2961f2af7b8'
SO_SHA256 = '5353b4967322798501cbc07eef62692576059a4badfc835a2de865f2054ca74c'
HEX_SHA256 = '1823e85250a6f9041fbce5a10ce7924fa5f4f222483b4ff7e583734d47b156b3'

def private(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),'wb') as f:
        f.write(data)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('xapk',type=Path);parser.add_argument('output',type=Path)
    args=parser.parse_args()
    if args.output.exists():parser.error('Output must not exist')
    data=args.xapk.read_bytes()
    if hashlib.sha256(data).hexdigest()!=XAPK_SHA256:parser.error('Unknown XAPK build')
    with zipfile.ZipFile(io.BytesIO(data)) as outer:
        base=outer.read('com.hex.tunnel.jotchuast.apk')
        arm=outer.read('config.arm64_v8a.apk')
    args.output.mkdir(parents=True,mode=0o700)
    with zipfile.ZipFile(io.BytesIO(arm)) as z:
        library=z.read('lib/arm64-v8a/libkovsec.so')
        native=z.read('lib/arm64-v8a/libhexvpn.so')
    if hashlib.sha256(library).hexdigest()!=SO_SHA256 or hashlib.sha256(native).hexdigest()!=HEX_SHA256:
        raise ValueError('Native build mismatch')
    private(args.output/'libkovsec.so',library);private(args.output/'libhexvpn.so',native)
    from elf_inspect import ElfImage
    image=ElfImage(args.output/'libkovsec.so')
    def u32(address):return struct.unpack('<I',image.read(address,4))[0]
    key=image.read(0x24210,8)
    pool=bytes(v^key[i%8] for i,v in enumerate(image.read(0x2c06a8,0x451e1)))
    def string(index):
        offset=u32(0x27c58+index*4)
        return pool[offset:pool.index(0,offset)].decode()
    reloc={r['r_offset']:r['r_addend'] for r in image.relocations if r['r_info_type']==1027}
    cls,start,count=struct.unpack('<III',image.read(0x269c8+159*12,12))
    if string(u32(0x302d8+cls*4))!='com/hexapplications/hexvpn/ui/servers/CustomServerShare' or count!=10:
        raise ValueError('Unexpected CustomServerShare map')
    methods=[]
    for i in range(start,start+count):
        address=0x2a2208+i*16
        name,signature,target=struct.unpack('<IIQ',image.read(address,16))
        methods.append({'name':string(name),'signature':string(signature),'address':hex(reloc.get(address+8,target))})
    with zipfile.ZipFile(io.BytesIO(base)) as z:
        manifest=json.loads(z.read('assets/protection/manifest.json'))
        build=manifest['build_id'];h=0xcbf29ce484222325
        for b in build.encode():h=((h^b)*0x100000001b3)&0xffffffffffffffff
        pkg_key=bytes(a^b for a,b in zip(image.read(0x76a54,32),image.read(0x76ab4,32)))
        packages=[]
        for i in range(3):
            name=f'assets/protection/kovsec-{i:03}.bin';wire=z.read(name)
            entry=next(x for x in manifest['files'] if x['path']==name)
            if len(wire)!=entry['size'] or hashlib.sha256(wire).hexdigest()!=entry['sha256']:
                raise ValueError('Package digest mismatch')
            cipher=ChaCha20_Poly1305.new(key=pkg_key,nonce=wire[:12])
            cipher.update(b'KXPKG1\x01\x00'+struct.pack('<QI',h,i))
            plain=cipher.decrypt_and_verify(wire[12:-16],wire[-16:])
            magic,version,ident,flags,code_size,handlers,zero,zero2=struct.unpack('<4s7I',plain[:32])
            if magic!=b'KXB1' or version!=1 or ident!=i or flags or zero or zero2 or 32+code_size+handlers!=len(plain):
                raise ValueError('Invalid authenticated package framing')
            private(args.output/f'package-{i}.bin',plain)
            packages.append({'id':i,'bytes':len(plain),'codeBytes':code_size,'handlerBytes':handlers,'sha256':hashlib.sha256(plain).hexdigest()})
    private(args.output/'file-methods.json',json.dumps({'build':build,'methods':methods,'packages':packages,
        'manifestSignatureVerified':False,'packageAeadVerified':True},indent=2).encode())
    print(json.dumps({'packageAeadVerified':True,'packages':len(packages),'methods':len(methods)}))

if __name__=='__main__':main()
