#!/usr/bin/env python3
"""Offline ASCII string/ELF inventory; private output only, no APK execution."""
import argparse,hashlib,json,re
from pathlib import Path
from elftools.elf.elffile import ELFFile

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('library',type=Path);p.add_argument('private_output',type=Path)
    a=p.parse_args();data=a.library.read_bytes()
    strings=[{'offset':m.start(),'text':m.group().decode('ascii')} for m in re.finditer(rb'[\x20-\x7e]{5,}',data)]
    with a.library.open('rb') as f:
        elf=ELFFile(f);sections=[{'name':s.name,'address':s['sh_addr'],'offset':s['sh_offset'],'bytes':s['sh_size']} for s in elf.iter_sections()]
    report={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'sections':sections,'strings':strings}
    a.private_output.touch(mode=0o600,exist_ok=True);a.private_output.chmod(0o600)
    a.private_output.write_text(json.dumps(report,indent=2))
    print(json.dumps({'bytes':len(data),'sha256':report['sha256'],'strings':len(strings),'sections':len(sections)}))
if __name__=='__main__':main()
