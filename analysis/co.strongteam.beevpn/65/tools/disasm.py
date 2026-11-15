import struct, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
p = '/home/hatch/workspace/catalogs/beevpn/extract/config.arm64_v8a/lib/arm64-v8a/libgojni.so'
data = open(p,'rb').read()
# ELF64 section headers
e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
e_shentsize, e_shnum = struct.unpack_from('<HH', data, 0x3a)
secs = {}
for i in range(e_shnum):
    off = e_shoff + i*e_shentsize
    name, typ, flags, addr, offset, size = struct.unpack_from('<IIQQQQ', data, off)
    secs[i] = (name, addr, offset, size)
# shstrtab
shstr = secs[e_shnum-1] if False else None
# get section names via shstrtab index
e_shstrndx = struct.unpack_from('<H', data, 0x3e)[0]
s = secs[e_shstrndx]
strtab = data[s[2]:s[2]+s[3]]
def secname(n):
    end = strtab.index(b'\0', n)
    return strtab[n:end].decode()
sections = {}
for i,(name,addr,off,size) in secs.items():
    sections[secname(name)] = (addr, off, size)
text_addr, text_off, text_size = sections['.text']
rod_addr, rod_off, rod_size = sections['.rodata']
def va2off(va):
    if text_addr <= va < text_addr+text_size: return text_off + (va-text_addr)
    if rod_addr <= va < rod_addr+rod_size: return rod_off + (va-rod_addr)
    return None
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
def dis(start, end, label=''):
    code = data[va2off(start):va2off(end)]
    print(f'--- {label} {start:#x}..{end:#x} ---')
    for ins in md.disasm(code, start):
        print(f'{ins.address:#x}: {ins.mnemonic:8} {ins.op_str}')
        # resolve ADRP+ADD pairs and BL targets
        if ins.mnemonic == 'bl':
            print(f'    ; BL target {ins.op_str}')
    return
for name, addr, size in [('DO',0x106ab34,120),('EO',0x106abac,120),('Encrypt',0x106ac24,120),('CU',0x106aa80,100),('GFC',0x106ad00,100)]:
    dis(addr, addr+size, name)
