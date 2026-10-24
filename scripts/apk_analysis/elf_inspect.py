#!/usr/bin/env python3
"""Offline AArch64 ELF inspection with symbol/PLT labels; never execute a library."""
from __future__ import annotations
import argparse
import io
import json
import struct
from pathlib import Path
from elftools.elf.elffile import ELFFile


class ElfImage:
    def __init__(self,path):
        self.data=Path(path).read_bytes();self.elf=ELFFile(io.BytesIO(self.data))
        if self.elf['e_machine']!='EM_AARCH64':raise ValueError('Expected AArch64 ELF')
        self.symbols={};self.names={};self.plt={};self.relocations=[]
        for name in ('.dynsym','.symtab'):
            section=self.elf.get_section_by_name(name)
            if section:
                for s in section.iter_symbols():
                    if s.name and s['st_value']:
                        self.symbols[s['st_value']]=s.name;self.names[s.name]=(s['st_value'],s['st_size'])
        section=self.elf.get_section_by_name('.rela.plt');plt=self.elf.get_section_by_name('.plt')
        if section and plt:
            syms=self.elf.get_section(section['sh_link'])
            # Linkers can emit 16-byte or BTI-padded 24-byte AArch64 entries.
            # Resolve each ADRP/LDR through its GOT relocation, not entry order.
            from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
            got={r['r_offset']:syms.get_symbol(r['r_info_sym']).name for r in section.iter_relocations()}
            instructions=list(Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN).disasm(plt.data(),plt['sh_addr']))
            for i,ins in enumerate(instructions[:-1]):
                if ins.mnemonic!='adrp' or not ins.op_str.startswith('x16, #'):continue
                following=instructions[i+1]
                if following.mnemonic!='ldr' or not following.op_str.startswith('x17, [x16'):continue
                page=int(ins.op_str.split('#')[1],0)
                offset=int(following.op_str.split('#')[1].rstrip(']'),0) if '#' in following.op_str else 0
                name=got.get(page+offset)
                if name:
                    self.plt[ins.address]=name
                    if i and instructions[i-1].mnemonic=='bti':self.plt[instructions[i-1].address]=name
        for section in self.elf.iter_sections():
            if section['sh_type']=='SHT_RELA':self.relocations.extend(dict(r.entry) for r in section.iter_relocations())

    def read(self,address,size):
        if size<0:raise ValueError('Invalid size')
        for s in self.elf.iter_segments():
            start=s['p_vaddr'];end=start+s['p_filesz']
            if start<=address and address+size<=end:
                off=s['p_offset']+address-start;return self.data[off:off+size]
        raise ValueError('Address outside file-backed segments')

    def cstring(self,address,limit=1024):
        out=bytearray()
        for i in range(limit):
            b=self.read(address+i,1)
            if b==b'\0':return out.decode('utf-8')
            out.extend(b)
        raise ValueError('Unterminated string')

    def jni_table(self, address, count):
        """Resolve JNINativeMethod triples from a known RegisterNatives table."""
        if not 1 <= count <= 128: raise ValueError('JNI count must be 1..128')
        relative = {r['r_offset']: r['r_addend'] for r in self.relocations if r['r_info_type'] == 1027}
        for index in range(count):
            pointers = [relative.get(address + index * 24 + offset,
                        struct.unpack('<Q', self.read(address + index * 24 + offset, 8))[0])
                        for offset in (0, 8, 16)]
            yield {'name': self.cstring(pointers[0]), 'signature': self.cstring(pointers[1]),
                   'address': hex(pointers[2])}

    def disassemble(self,address,size):
        from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
        for ins in Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN).disasm(self.read(address,size),address):
            label=''
            if ins.mnemonic in ('b','bl') and ins.op_str.startswith('#'):
                target=int(ins.op_str[1:],0);label=self.plt.get(target,self.symbols.get(target,''))
            yield f'{ins.address:#x} {ins.mnemonic} {ins.op_str} {label}'.rstrip()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('file',type=Path)
    modes=p.add_mutually_exclusive_group()
    modes.add_argument('--disassemble',type=lambda x:int(x,0))
    modes.add_argument('--jni-table',type=lambda x:int(x,0))
    p.add_argument('--count',type=int,default=1)
    p.add_argument('--size',type=lambda x:int(x,0),default=256)
    a=p.parse_args();elf=ElfImage(a.file)
    if a.disassemble is not None:
        if not 0<a.size<=65536:p.error('Size must be 1..65536')
        print('\n'.join(elf.disassemble(a.disassemble,a.size)))
    elif a.jni_table is not None:print(json.dumps(list(elf.jni_table(a.jni_table,a.count)),indent=2))
    else:print(json.dumps({name:{'address':hex(addr),'size':size} for name,(addr,size) in elf.names.items() if name.startswith(('Java_','JNI_'))},indent=2))

if __name__=='__main__':main()
