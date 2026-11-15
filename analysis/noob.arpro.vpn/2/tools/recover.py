#!/usr/bin/env python3
"""Offline pinned NoobCrypt native constants and included catalog inspection.

JNI b calls 0x47a4b8; mode5 AES-256-XTS, mode0 GCM, mode1 CBC.
Keys are format constants, not request authentication. No SO/JNI executed.
"""
import argparse,base64,hashlib,json,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from scripts.apk_analysis.elf_inspect import ElfImage
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from Crypto.Cipher import AES
NATIVE_SHA='e4388396c5b5e7c4da6b22db50cb43605509b0c6cae75526fe20f45be6aebd32'
def keys(native):
    assert hashlib.sha256(native.read_bytes()).hexdigest()==NATIVE_SHA
    elf=ElfImage(native)
    short=bytes(a^b for a,b in zip(elf.read(0x21d6e0,32),elf.read(0x1c2b80,16)+elf.read(0x1c2860,16)))
    mask=b''.join(elf.read(x,16) for x in [0x1c2000,0x1c21c0,0x1c2aa0,0x1c2ab0])
    rotated=bytes(a^b for a,b in zip(elf.read(0x21d8d0,64),mask))
    xts=bytes(((x>>2)|(x<<6))&255 for x in rotated)
    return short,xts
def b64(value):return base64.b64decode(re.sub(rb'\s+',b'',value if isinstance(value,bytes) else value.encode()),validate=True)
def xts_open(value,key):
    raw=b64(value);context=Cipher(algorithms.AES(key),modes.XTS(raw[:16])).decryptor()
    return context.update(raw[16:])+context.finalize()
def gcm_open(value,key):
    raw=b64(value);return AES.new(key,AES.MODE_GCM,nonce=raw[:12]).decrypt_and_verify(raw[12:-16],raw[-16:]).decode('utf-8')
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args();d=a.private
    short,xts=keys(d/'unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libovpn3.so')
    outer=json.loads(xts_open((d/'noobdev.js').read_bytes(),xts));decoded=outer.copy()
    report={'native_sha256':NATIVE_SHA,'field_key_sha256':hashlib.sha256(short).hexdigest(),
        'outer_key_sha256':hashlib.sha256(xts).hexdigest(),'outer_keys':list(outer),'root_decoded':[]}
    for k,v in outer.items():
        if isinstance(v,str) and v:
            try:decoded[k]=gcm_open(v,short);report['root_decoded'].append(k)
            except (ValueError,UnicodeError):pass
    report['version']=decoded.get('Version');report['counts']={k:len(v) for k,v in outer.items() if isinstance(v,list)}
    report['update_urls']={k:decoded.get(k) for k in ['DefUpdateURL','updater']}
    for name,obj in [('constants.json',{'field':short.hex(),'outer':xts.hex()}),('included-outer.json',outer),('included-root.json',decoded)]:
        f=d/name;f.touch(mode=0o600,exist_ok=True);f.chmod(0o600);f.write_text(json.dumps(obj,ensure_ascii=False,indent=2))
    (d/'recovery.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':main()
