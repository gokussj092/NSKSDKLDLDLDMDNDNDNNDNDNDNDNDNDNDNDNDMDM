#!/usr/bin/env python3
"""Static Thumb ELF inspection only; no third-party native execution/emulation."""
import argparse,hashlib,re,struct
from io import BytesIO
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
def inspect(path,start=None,end=None,arm=False):
    raw=Path(path).read_bytes();e=ELFFile(BytesIO(raw))
    if e['e_machine']!='EM_ARM' or hashlib.sha256(raw).hexdigest()!='d36f50a2dcd3a6821d041d188ad492e9c6e681913508d05c3bfb10601603f700':raise ValueError('UNINSPECTED_ELF')
    def read(a,n):
        for s in e.iter_segments():
            if s['p_type']=='PT_LOAD' and s['p_vaddr']<=a and a+n<=s['p_vaddr']+s['p_filesz']:return raw[s['p_offset']+a-s['p_vaddr']:s['p_offset']+a-s['p_vaddr']+n]
        return b''
    if start is None:
        for sec in e.iter_sections():print(sec.name,hex(sec['sh_addr']),hex(sec['sh_size']))
        ex=e.get_section_by_name('.ARM.exidx');tab=ex.data()
        for n in range(0,len(tab),8):
            v=struct.unpack_from('<I',tab,n)[0];rel=v&0x7fffffff;rel=rel-(1<<31) if rel&(1<<30) else rel
            print('function',hex(ex['sh_addr']+n+rel))
        sec=e.get_section_by_name('.rodata')
        for a in range(sec['sh_addr'],sec['sh_addr']+sec['sh_size'],16):print(f'{a:08x} {read(a,16).hex()}')
        return
    cs=Cs(CS_ARCH_ARM,(CS_MODE_ARM if arm else CS_MODE_THUMB)|CS_MODE_LITTLE_ENDIAN);cs.skipdata=True
    instructions=list(cs.disasm(read(start,end-start),start))
    for i,op in enumerate(instructions):
        comment='';m=re.fullmatch(r'(r\d+), \[pc, #(0x[0-9a-f]+|\d+)\]',op.op_str)
        if op.mnemonic.startswith('ldr') and m:
            a=((op.address+4)&~3)+int(m[2],0);v=read(a,4)
            if len(v)==4:
                value=struct.unpack('<I',v)[0];comment=f' ; [{a:x}]={value:x}'
                for nxt in instructions[i+1:i+4]:
                    if nxt.mnemonic=='add' and nxt.op_str==m[1]+', pc':
                        target=(nxt.address+4+value)&0xffffffff;comment+=f' -> {target:x} {read(target,32)!r}';break
        print(f'{op.address:08x}: {op.mnemonic:10} {op.op_str}{comment}')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('library',type=Path);p.add_argument('--arm',action='store_true');p.add_argument('--start',type=lambda s:int(s,0));p.add_argument('--end',type=lambda s:int(s,0));a=p.parse_args();inspect(a.library,a.start,a.end,a.arm)
