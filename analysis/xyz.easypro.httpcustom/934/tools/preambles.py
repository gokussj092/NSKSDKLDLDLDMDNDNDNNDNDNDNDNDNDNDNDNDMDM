"""Locate compiler-generated local integrity preambles for an offline format probe.

Only applies within memory emulation; never changes an APK or remote validation.
Adapted from the retained build-914 preamble_map.py checkpoint recipe.
"""
from collections import deque
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN

def patches(image,panic):
    section=image.elf.get_section_by_name('.text')
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.skipdata=True
    history=deque(maxlen=66);loops=[]
    for address,size,mnemonic,operands in cs.disasm_lite(section.data(),section['sh_addr']):
        if history and mnemonic=='b' and operands.startswith('#'):
            prev=history[-1];target=int(operands[1:],0)
            if prev[2]=='bl' and prev[3]==f'#{panic:#x}' and 0<address-target<128:
                candidates=[i[0] for i in history if i[2]=='br' and i[0]<target]
                loops.append((target,address+4,candidates[-1] if candidates else None))
        history.append((address,size,mnemonic,operands))
    groups=[]
    for item in loops:
        if groups and item[0]-groups[-1][-1][1]<0x250:groups[-1].append(item)
        else:groups.append([item])
    return {g[0][2]:g[-1][1] for g in groups if len(g)==3 and g[0][2] is not None}
