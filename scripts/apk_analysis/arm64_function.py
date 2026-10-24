#!/usr/bin/env python3
"""Bounded offline emulation of isolated AArch64 ELF functions (no JNI/OS)."""
from __future__ import annotations
import struct
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_TPIDR_EL0, UC_ARM64_REG_PC
from elf_inspect import ElfImage


class Arm64Function:
    """Only relative relocations and memory helpers are supported; other imports fail."""
    STACK = 0x1000000
    TLS = 0x2000000
    HEAP = 0x3000000
    STOP = 0x4000000

    def __init__(self, path):
        self.image = ElfImage(path)
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        segments = [s for s in self.image.elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        end = max(s['p_vaddr'] + s['p_memsz'] for s in segments)
        self.uc.mem_map(0, (end + 4095) & ~4095)
        for segment in segments:
            self.uc.mem_write(segment['p_vaddr'], segment.data())
        for r in self.image.relocations:
            if r['r_info_type'] == 1027:  # R_AARCH64_RELATIVE, base zero
                self.uc.mem_write(r['r_offset'], struct.pack('<Q', r['r_addend']))
        for address, size in ((self.STACK, 0x100000), (self.TLS, 4096),
                              (self.HEAP, 0x1000000), (self.STOP, 4096)):
            self.uc.mem_map(address, size)
        self.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, self.TLS)
        self.next_alloc = self.HEAP
        self.observers = {}
        self.error = None
        self.uc.hook_add(UC_HOOK_CODE, self._step)

    def alloc(self, data):
        if isinstance(data, int):
            if data < 0: raise ValueError('Negative allocation')
            data = bytes(data)
        address = self.next_alloc
        self.next_alloc += (len(data) + 15) & ~15
        if self.next_alloc > self.HEAP + 0x1000000: raise ValueError('Heap exhausted')
        self.uc.mem_write(address, data)
        return address

    def read(self, address, size):
        return bytes(self.uc.mem_read(address, size))

    def reg(self, index):
        return self.uc.reg_read(UC_ARM64_REG_X0 + index)

    def _step(self, uc, address, size, _):
        try:
            if address in self.observers: self.observers[address](self)
            name = self.image.plt.get(address)
            if not name: return
            a, b, n = self.reg(0), self.reg(1), self.reg(2)
            if name in ('memcpy', '__memcpy_chk'):
                if name == '__memcpy_chk' and n > self.reg(3):
                    raise ValueError('Native memory copy exceeds destination')
                if n > 8 * 1024 * 1024: raise ValueError('Oversized copy')
                uc.mem_write(a, self.read(b, n))
            elif name == 'memset':
                if n > 8 * 1024 * 1024: raise ValueError('Oversized memset')
                uc.mem_write(a, bytes([b & 255]) * n)
            else:
                raise ValueError('Unsupported native import: ' + name)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
        except Exception as exc:
            self.error = exc
            uc.emu_stop()

    def call(self, address, *arguments, limit=5_000_000):
        self.error = None
        sp = self.STACK + 0xF0000
        self.uc.reg_write(UC_ARM64_REG_SP, sp)
        self.uc.reg_write(UC_ARM64_REG_X30, self.STOP)
        for index, value in enumerate(arguments[:8]):
            self.uc.reg_write(UC_ARM64_REG_X0 + index, value)
        for index, value in enumerate(arguments[8:]):
            self.uc.mem_write(sp + 8 * index, struct.pack('<Q', value))
        self.uc.emu_start(address, self.STOP, count=limit)
        if self.error: raise self.error
        if self.uc.reg_read(UC_ARM64_REG_PC) != self.STOP:
            raise ValueError('Native instruction limit reached')
        return self.reg(0)
