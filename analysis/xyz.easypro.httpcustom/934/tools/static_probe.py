"""Retained static panic-pattern and historical-constant locator experiment."""
import argparse,collections,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT/'scripts/apk_analysis'));sys.path.insert(0,str(ROOT))
from elf_inspect import ElfImage
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from decoders.Python._hc_hccfg import C0_PREFIX

def main():
    p=argparse.ArgumentParser();p.add_argument('library');a=p.parse_args();image=ElfImage(a.library)
    section=image.elf.get_section_by_name('.text');cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.skipdata=True
    previous=None;hits=collections.Counter()
    for address,size,mnemonic,operands in cs.disasm_lite(section.data(),section['sh_addr']):
        if previous and mnemonic=='b' and operands.startswith('#') and previous[0]=='bl' and 0<address-int(operands[1:],0)<128:
            hits[previous[1]]+=1
        previous=(mnemonic,operands)
    print('local preamble call patterns',hits.most_common(3))
    offset=image.data.find(C0_PREFIX[32:]);address=None
    if offset>=0:
        for segment in image.elf.iter_segments():
            if segment['p_offset']<=offset<segment['p_offset']+segment['p_filesz']:
                address=offset+segment['p_vaddr']-segment['p_offset'];break
    print('historical constant offset/address',None if offset<0 else hex(offset),None if address is None else hex(address))
    print('KDF compatibility inferred: false')

if __name__=='__main__':main()
