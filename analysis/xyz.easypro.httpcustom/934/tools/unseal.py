"""Run bounded ELF memory initializers offline; no JNI, OS, network or app lifecycle."""
import argparse, struct, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'scripts/apk_analysis'))
from arm64_function import Arm64Function
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_PC
from preambles import patches

def main():
    p=argparse.ArgumentParser();p.add_argument('library',type=Path);p.add_argument('output',type=Path)
    a=p.parse_args()
    if a.output.resolve().is_relative_to(ROOT): raise ValueError('Private binary must stay outside Git')
    Arm64Function.STACK=0x10000000;Arm64Function.TLS=0x11000000
    Arm64Function.HEAP=0x12000000;Arm64Function.STOP=0x14000000
    e=Arm64Function(a.library);s=e.image.elf.get_section_by_name('.init_array')
    e.uc.hook_del(e.step_hook)
    for address in e.image.plt: e.uc.hook_add(UC_HOOK_CODE,e._step,begin=address,end=address)
    panic=0x66b480 if 'runtime' in a.library.name else 0xe6eda0
    pm=patches(e.image,panic)
    print('local format-probe preambles',len(pm))
    for address,target in pm.items():
        e.uc.hook_add(UC_HOOK_CODE,lambda u,a,s,d,t=target:u.reg_write(UC_ARM64_REG_PC,t),begin=address,end=address)
    for i in range(0,s['sh_size'],8):
        address=struct.unpack('<Q',e.read(s['sh_addr']+i,8))[0]
        try:e.call(address,limit=50_000_000)
        except Exception as error:print(hex(address),type(error).__name__,str(error))
    raw=bytearray(e.image.data)
    for seg in e.image.elf.iter_segments():
        if seg['p_type']=='PT_LOAD':raw[seg['p_offset']:seg['p_offset']+seg['p_filesz']]=e.read(seg['p_vaddr'],seg['p_filesz'])
    a.output.write_bytes(raw)
    import json
    a.output.with_suffix('.preambles.json').write_text(json.dumps(pm))

if __name__=='__main__':main()
