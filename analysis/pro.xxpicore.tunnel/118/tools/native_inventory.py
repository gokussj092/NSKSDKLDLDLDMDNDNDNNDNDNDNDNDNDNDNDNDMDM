#!/usr/bin/env python3
"""Inspect Renz/crypto symbols offline; no library startup or JNI execution."""
import argparse,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT/'scripts/apk_analysis'))
from elf_inspect import ElfImage
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('native',type=Path);p.add_argument('private_output',type=Path);a=p.parse_args()
    elf=ElfImage(a.native)
    selected={n:{'address':hex(v),'size':s} for n,(v,s) in elf.names.items() if any(x in n.lower() for x in ('renz','xxtea','threefish','hkdf','pbkdf','key_seed','fixed_salt','decryptmain','decryptspecial','decryptsensitive'))}
    result={'sha256':hashlib.sha256(a.native.read_bytes()).hexdigest(),'symbols':selected}
    a.private_output.write_text(json.dumps(result,indent=2)+'\n');a.private_output.chmod(0o600)
    print(json.dumps(result))
if __name__=='__main__':main()
