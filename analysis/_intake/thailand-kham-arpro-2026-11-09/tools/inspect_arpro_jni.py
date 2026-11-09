#!/usr/bin/env python3
"""Read the statically identified NoobCrypt registration table, never execute ELF."""
import argparse,hashlib,json,struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from recover_arpro import EXPECTED
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('library',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    if hashlib.sha256(a.library.read_bytes()).hexdigest()!=EXPECTED:raise ValueError('NATIVE_BUILD_MISMATCH')
    with a.library.open('rb') as f:
        elf=ELFFile(f);rel={r['r_offset']:r['r_addend'] for r in elf.get_section_by_name('.rela.dyn').iter_relocations()}
        def raw(address,n):
            s=next(s for s in elf.iter_sections() if s['sh_addr']<=address<s['sh_addr']+s['sh_size'])
            return s.data()[address-s['sh_addr']:address-s['sh_addr']+n]
        def pointer(address):return rel.get(address,struct.unpack('<Q',raw(address,8))[0])
        def string(address):return raw(address,256).split(b'\0')[0].decode()
        methods=[]
        for i in range(10):
            at=0x822c48+i*24
            methods.append(dict(name=string(pointer(at)),signature=string(pointer(at+8)),address=hex(pointer(at+16))))
    a.output.write_text(json.dumps(dict(librarySha256=EXPECTED,methods=methods,nativeCodeExecuted=False),indent=2)+'\n')
