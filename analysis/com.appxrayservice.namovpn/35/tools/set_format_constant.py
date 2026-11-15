#!/usr/bin/env python3
"""Reproduce the reviewed inline format constant, never an HTTP credential."""
import argparse,hashlib,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from scripts.apk_analysis.elf_inspect import ElfImage
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('native',type=Path);a=p.parse_args()
    assert hashlib.sha256(a.native.read_bytes()).hexdigest()=='c12426484f92371508ac44c9c207a03d1da4a2a97ec1e0ad5486effc95e17ebf'
    key=ElfImage(a.native).cstring(0x541).encode('utf-8')
    assert hashlib.sha256(key).hexdigest()=='2f3cb6bebbf6d6ba8d4b69c4c968aac9f5eacf434e8a49b3f4a47e7647420ee6'
    f=ROOT/'decoders/Python/apps/NAMO_VPN/codec.py'
    text,count=re.subn(r'^FORMAT_KEY = .*$',lambda _: 'FORMAT_KEY = '+repr(key)+' # MainDetail.b, static format constant from libapi-namo.so',f.read_text(),flags=re.MULTILINE)
    assert count==1;f.write_text(text);print('Reviewed format constant matches pinned JNI source.')
if __name__=='__main__':main()
