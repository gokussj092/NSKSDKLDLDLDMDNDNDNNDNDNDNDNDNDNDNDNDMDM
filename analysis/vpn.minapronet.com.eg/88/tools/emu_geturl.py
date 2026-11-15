#!/usr/bin/env python3
"""Emulate libminacore.so nativeGetConfigUrl under Unicorn to recover the
primary catalog (updater) URL, which is built obfuscated in native code
(0x104538) and never appears as a plain string in the DEX or the .so.

Approach (same harness pattern as slowdns/work/emu_jni.py):
- map the .so PT_LOADs at BASE, apply RELATIVE relocs
- patch PLT/GOT imports with tiny stubs (malloc/memset/pthread stubs)
- fake JNIEnv whose NewStringUTF (table idx 167, offset 0x538) captures the
  returned URL string
- call Java_vpn_minapronet_com_eg_security_MinaCore_nativeGetConfigUrl
  (0x10423c) with x0=fake JNIEnv; read the captured string.
"""
import struct, sys
from unicorn import *
from unicorn.arm64_const import *

SO = '/home/hatch/workspace/catalogs/minapronet/work/so/lib/arm64-v8a/libminacore.so'
BASE = 0x10000000
STACK_ADDR = 0x70000000
STACK_SIZE = 0x100000
TLS_ADDR = 0x71000000
STUB_ADDR = 0x72000000
STUB_SIZE = 0x10000
FAKEENV_ADDR = 0x73001000
FAKEENV_TBL = 0x73002000
HEAP_ADDR = 0x74000000
HEAP_SIZE = 0x1000000
RET_ADDR = 0x60000000

data = open(SO, 'rb').read()

def u16(o): return struct.unpack_from('<H', data, o)[0]
def u32(o): return struct.unpack_from('<I', data, o)[0]
def u64(o): return struct.unpack_from('<Q', data, o)[0]

e_phoff = u64(0x20); e_phentsize = u16(0x36); e_phnum = u16(0x38)
loads = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, p_flags = u32(off), u32(off+4)
    p_offset, p_vaddr, p_filesz, p_memsz = u64(off+8), u64(off+16), u64(off+32), u64(off+40)
    if p_type == 1:
        loads.append((p_offset, p_vaddr, p_filesz, p_memsz, p_flags))

e_shoff = u64(0x28); e_shentsize = u16(0x3a); e_shnum = u16(0x3c); e_shstrndx = u16(0x3e)
sections = {}
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    sh_name, sh_type = u32(off), u32(off+4)
    sh_offset, sh_size = u64(off+0x18), u64(off+0x20)
    sh_link, sh_entsize = u32(off+0x28), u64(off+0x38)
    sections[i] = (sh_name, sh_type, sh_offset, sh_size, sh_link, sh_entsize)
shstr = sections[e_shstrndx]
def secname(nidx):
    o = shstr[2] + nidx; e = data.index(b'\x00', o); return data[o:e].decode()
sec_by_name = {secname(s[0]): s for s in sections.values()}
dynsym_sec, dynstr_sec = sec_by_name['.dynsym'], sec_by_name['.dynstr']
nsyms = dynsym_sec[3] // dynsym_sec[5]
syms = []
for i in range(nsyms):
    off = dynsym_sec[2] + i * dynsym_sec[5]
    st_name = u32(off); st_value, st_size = u64(off+8), u64(off+16)
    nm = ''
    if st_name:
        o = dynstr_sec[2] + st_name; e = data.index(b'\x00', o); nm = data[o:e].decode()
    syms.append((nm, st_value))

def parse_rela(sec):
    out = []
    for i in range(sec[3] // sec[5]):
        off = sec[2] + i * sec[5]
        r_off, r_info, r_add = struct.unpack_from('<QQq', data, off)
        out.append((r_off, r_info >> 32, r_info & 0xffffffff, r_add))
    return out
rela_dyn = parse_rela(sec_by_name['.rela.dyn'])
rela_plt = parse_rela(sec_by_name['.rela.plt'])

NATIVE_GET_CONFIG_URL = None
for nm, val in syms:
    if nm == 'Java_vpn_minapronet_com_eg_security_MinaCore_nativeGetConfigUrl':
        NATIVE_GET_CONFIG_URL = val
print('nativeGetConfigUrl at', hex(NATIVE_GET_CONFIG_URL))

uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
for (po, pv, pf, pm, fl) in loads:
    addr = BASE + pv
    map_start = addr & ~0xfff
    map_end = (addr + pm + 0xfff) & ~0xfff
    uc.mem_map(map_start, map_end - map_start, UC_PROT_ALL)
    uc.mem_write(addr, data[po:po+pf])
    if pm > pf:
        uc.mem_write(addr + pf, b'\x00' * (pm - pf))
uc.mem_map(STACK_ADDR, STACK_SIZE, UC_PROT_ALL)
uc.mem_map(TLS_ADDR, 0x1000, UC_PROT_ALL)
uc.mem_map(STUB_ADDR, STUB_SIZE, UC_PROT_ALL)
uc.mem_map(FAKEENV_ADDR, 0x10000, UC_PROT_ALL)
uc.mem_map(HEAP_ADDR, HEAP_SIZE, UC_PROT_ALL)
uc.mem_map(RET_ADDR, 0x1000, UC_PROT_ALL)

for (r_off, r_sym, r_type, r_add) in rela_dyn:
    if r_type == 1027:  # R_AARCH64_RELATIVE
        uc.mem_write(BASE + r_off, struct.pack('<Q', BASE + r_add))

CANARY = 0x1122334455667788
uc.mem_write(TLS_ADDR + 0x28, struct.pack('<Q', CANARY))
uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS_ADDR)

heap_ptr = [HEAP_ADDR]
captured = {'url': None}
call_log = []

STUB_RET0 = bytes.fromhex('e0031faac0035fd6')  # mov x0, xzr ; ret
STUB_RET1 = bytes.fromhex('20008052c0035fd6')  # mov x0, #1 ; ret

# PLT imports -> stubs
plt_imports = {}
for (r_off, r_sym, r_type, r_add) in rela_plt:
    nm = syms[r_sym][0] if r_sym < len(syms) else '?'
    plt_imports[r_off] = nm
# GLOB_DAT imports in rela.dyn with a symbol name
for (r_off, r_sym, r_type, r_add) in rela_dyn:
    if r_type == 1025 and r_sym < len(syms) and syms[r_sym][0]:
        plt_imports[r_off] = syms[r_sym][0]
print('imports to stub:', len(plt_imports))
stub_of = {}
for j, (got_off, nm) in enumerate(sorted(plt_imports.items())):
    stub = STUB_ADDR + j * 0x40
    uc.mem_write(stub, STUB_RET0)
    uc.mem_write(BASE + got_off, struct.pack('<Q', stub))
    stub_of[stub] = nm

# fake JNIEnv: NewStringUTF at table idx 167
NEWSTRINGUTF_IDX = 167
GETSTRINGUTFCHARS_IDX = 165
jni_stub_base = STUB_ADDR + 0x8000
for idx in range(232):
    addr = jni_stub_base + idx * 16
    uc.mem_write(addr, STUB_RET1)
    uc.mem_write(FAKEENV_TBL + idx * 8, struct.pack('<Q', addr))
uc.mem_write(FAKEENV_ADDR, struct.pack('<Q', FAKEENV_TBL))

def hook_code(uc, address, size, user_data):
    if address == RET_ADDR:
        uc.emu_stop()
        return
    if STUB_ADDR <= address < STUB_ADDR + 0x8000:
        j = (address - STUB_ADDR) // 0x40
        items = sorted(plt_imports.items())
        if j < len(items):
            nm = items[j][1]
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            x2 = uc.reg_read(UC_ARM64_REG_X2)
            call_log.append(('plt', nm, hex(address)))
            if nm in ('memcpy', '__memcpy_chk', 'memmove'):
                n = x2
                uc.mem_write(x0, bytes(uc.mem_read(x1, n)))
                uc.reg_write(UC_ARM64_REG_X0, x0)
            elif nm == 'memset':
                uc.mem_write(x0, bytes([x1 & 0xff]) * x2)
                uc.reg_write(UC_ARM64_REG_X0, x0)
            elif nm in ('strlen', 'strnlen'):
                try:
                    s = bytes(uc.mem_read(x0, 4096)).split(b'\x00')[0]
                    uc.reg_write(UC_ARM64_REG_X0, len(s))
                except UcError:
                    uc.reg_write(UC_ARM64_REG_X0, 0)
            elif nm in ('malloc', '_Znwm', '_ZnwmRKSt9nothrow_t', 'calloc'):
                p = heap_ptr[0]
                heap_ptr[0] += (x0 + 0xfff) & ~0xfff
                uc.reg_write(UC_ARM64_REG_X0, p)
            elif nm in ('free', '_ZdlPvm', 'pthread_mutex_lock', 'pthread_mutex_unlock',
                        'pthread_once', '__cxa_atexit', '__cxa_guard_acquire',
                        '__cxa_guard_release', 'abort', 'fclose'):
                uc.reg_write(UC_ARM64_REG_X0, 0)
            else:
                uc.reg_write(UC_ARM64_REG_X0, 0)
            # return: emulate ret by jumping to LR
            lr = uc.reg_read(UC_ARM64_REG_X30)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return
    if jni_stub_base <= address < jni_stub_base + 232 * 16:
        idx = (address - jni_stub_base) // 16
        if idx == NEWSTRINGUTF_IDX:
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            try:
                s = bytes(uc.mem_read(x1, 4096)).split(b'\x00')[0]
            except UcError:
                s = b'<unreadable>'
            captured['url'] = s
            print('NewStringUTF captured:', s)
            uc.reg_write(UC_ARM64_REG_X0, 0x1234)
            lr = uc.reg_read(UC_ARM64_REG_X30)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return
        call_log.append(('jni', idx, hex(address)))
        uc.reg_write(UC_ARM64_REG_X0, 0)
        lr = uc.reg_read(UC_ARM64_REG_X30)
        uc.reg_write(UC_ARM64_REG_PC, lr)
        return

uc.hook_add(UC_HOOK_CODE, hook_code)

uc.reg_write(UC_ARM64_REG_SP, STACK_ADDR + STACK_SIZE - 0x1000)
uc.reg_write(UC_ARM64_REG_X30, RET_ADDR)
uc.reg_write(UC_ARM64_REG_X0, FAKEENV_ADDR)  # JNIEnv*
uc.reg_write(UC_ARM64_REG_X1, 0)             # jclass
uc.reg_write(UC_ARM64_REG_X2, 0)             # Context (unused by this fn)

try:
    uc.emu_start(BASE + NATIVE_GET_CONFIG_URL, RET_ADDR, count=2000000)
except UcError as e:
    print('UcError:', e, 'at PC', hex(uc.reg_read(UC_ARM64_REG_PC)))
    print('x0 =', hex(uc.reg_read(UC_ARM64_REG_X0)))

print('return x0 =', hex(uc.reg_read(UC_ARM64_REG_X0)))
print('captured URL:', captured['url'])
print('PLT calls:', call_log[:30])
