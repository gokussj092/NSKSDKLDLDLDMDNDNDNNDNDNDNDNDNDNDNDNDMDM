#!/usr/bin/env python3
"""Recover build-pinned static cipher material; open the real public outer layer."""
import argparse,base64,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'scripts/apk_analysis'))
from elf_inspect import ElfImage
from decoders.Python import renz
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
NATIVE_SHA='7ead852bccaa5b17f62d145ea97915f7ea04c579891576f8466a22bb48dd2765'
def write(p,data):
    p.touch(mode=0o600,exist_ok=True);p.chmod(0o600);p.write_text(json.dumps(data,indent=2,ensure_ascii=False)+'\n')
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args();d=a.private
    native=d/'unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libovpn3.so'
    assert hashlib.sha256(native.read_bytes()).hexdigest()==NATIVE_SHA
    elf=ElfImage(native)
    material={'KEY_SEED':elf.read(0x20ad38,32),'IV':elf.read(0x20ad58,16),'FIXED_SALT':elf.read(0x20add4,32)}
    assert elf.read(0x20ad18,16)==material['FIXED_SALT'][:16]
    write(d/'material.json',{k:v.hex() for k,v in material.items()})
    key=hashlib.sha256(material['KEY_SEED']).digest()[:16]
    raw=base64.b64decode((d/'remote.bin').read_text().strip(),validate=True)
    value=unpad(AES.new(key,AES.MODE_CBC,material['IV']).decrypt(raw),16)
    plain,n=renz.renz_xxtea_decrypt_custom(value,key);assert n
    doc=json.loads(plain.decode('utf-8'));write(d/'outer.json',doc)
    report={'nativeSha256':NATIVE_SHA,'outerBytes':len(plain),'outerSha256':hashlib.sha256(plain).hexdigest(),
      'version':doc.get('Version'),'servers':len(doc.get('Servers',[])),'networks':len(doc.get('Networks',[])),
      'rootKeys':list(doc),'materialMatchesXhypher':{k:v==renz.RENZ_KEYS['xhypher'][k] for k,v in material.items()}}
    write(d/'recovery-summary.json',report);print(json.dumps(report))
if __name__=='__main__':main()
