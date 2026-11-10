"""Read-only ELF disassembly/constant references for the supplied HTTP Custom APK."""
import argparse
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('library',type=Path)
    parser.add_argument('--start',type=lambda s:int(s,0))
    parser.add_argument('--size',type=lambda s:int(s,0),default=0x300)
    parser.add_argument('--page',type=lambda s:int(s,0))
    args=parser.parse_args()
    with args.library.open('rb') as stream:
        elf=ELFFile(stream)
        text=elf.get_section_by_name('.text')
        md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
        instructions=list(md.disasm(text.data(),text['sh_addr']))
        if args.page is not None:
            chosen=set()
            for i,ins in enumerate(instructions):
                if ins.mnemonic=='adrp' and f'#0x{args.page:x}' in ins.op_str:
                    chosen.update(range(max(0,i-3),min(len(instructions),i+12)))
        else:
            chosen={i for i,ins in enumerate(instructions)if args.start<=ins.address<args.start+args.size}
        for i in sorted(chosen):
            ins=instructions[i];print(f'{ins.address:08x}: {ins.mnemonic} {ins.op_str}')

if __name__=='__main__':main()
