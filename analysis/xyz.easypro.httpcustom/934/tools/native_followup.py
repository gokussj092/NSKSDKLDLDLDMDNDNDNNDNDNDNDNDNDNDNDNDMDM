"""Offline disassembly and public-prestate immediate locator for build 934.

No host execution of Android libraries and no capture of user/session keys.
"""
import argparse,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT/'scripts/apk_analysis'))
from elf_inspect import ElfImage
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN

def main():
    p=argparse.ArgumentParser();p.add_argument('library',type=Path)
    p.add_argument('--address',type=lambda s:int(s,0));p.add_argument('--size',type=lambda s:int(s,0),default=0x800)
    p.add_argument('--scan-public-prestate',action='store_true');a=p.parse_args()
    e=ElfImage(a.library);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.skipdata=True
    if a.scan_public_prestate:
        section=e.elf.get_section_by_name('.text');hits=[]
        for addr,size,mnemonic,operands in cs.disasm_lite(section.data(),section['sh_addr']):
            if mnemonic in ('mov','movk','movz') and any(s in operands for s in ('#0x3a1e','#0xaabd','#0xa211','#0x3d63')):
                hits.append({'address':hex(addr),'instruction':mnemonic+' '+operands})
        print(json.dumps(hits,indent=2));return
    if a.address is None:raise ValueError('Select disassembly or scan')
    for seg in e.elf.iter_segments():
        if seg['p_type']=='PT_LOAD' and seg['p_vaddr']<=a.address<seg['p_vaddr']+seg['p_filesz']:
            offset=a.address-seg['p_vaddr']+seg['p_offset'];raw=e.data[offset:offset+a.size];break
    else:raise ValueError('Unmapped file address')
    for addr,size,mnemonic,operands in cs.disasm_lite(raw,a.address):
        annotation=''
        if mnemonic in ('bl','b') and operands.startswith('#'):
            target=int(operands[1:],0);annotation=e.plt.get(target,'')
        print(f'{addr:08x}  {mnemonic:<8} {operands}'+(' ; '+annotation if annotation else ''))

if __name__=='__main__':main()
