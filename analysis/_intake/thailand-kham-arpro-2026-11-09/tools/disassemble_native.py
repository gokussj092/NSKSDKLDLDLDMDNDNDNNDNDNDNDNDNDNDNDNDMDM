#!/usr/bin/env python3
"""Static ARM64 ELF disassembly; never load or execute the vendor library."""
import argparse
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('library',type=Path);p.add_argument('address',type=lambda x:int(x,0));p.add_argument('size',type=lambda x:int(x,0));p.add_argument('output',type=Path);a=p.parse_args()
    with a.library.open('rb') as f:
        elf=ELFFile(f);sec=next(s for s in elf.iter_sections() if s['sh_addr']<=a.address<s['sh_addr']+s['sh_size'])
        off=a.address-sec['sh_addr'];code=sec.data()[off:off+a.size]
        rows=[f'{i.address:x}: {i.mnemonic} {i.op_str}' for i in Cs(CS_ARCH_ARM64,CS_MODE_ARM).disasm(code,a.address)]
        a.output.write_text('\n'.join(rows)+'\n');print('instructions:',len(rows))
