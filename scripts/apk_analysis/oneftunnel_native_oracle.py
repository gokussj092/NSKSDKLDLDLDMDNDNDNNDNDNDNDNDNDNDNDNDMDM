#!/usr/bin/env python3
"""Original ARM64 KDF, bounded and offline; JNI HMAC is modeled with host HMAC.

Root reconstruction/NEON and HKDF composition run original instructions. No
Android startup, network or unknown imports. Only the known SO hash is accepted.
"""
from __future__ import annotations
import hashlib
import hmac
from pathlib import Path
import struct
from arm64_function import Arm64Function
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X0, UC_ARM64_REG_X30

SO_SHA256 = "b46e85425e6512a39bd5fde5cd5037bef7ed065ab27c704b96ce40aa3a24e0ff"


class Native(Arm64Function):
    def __init__(self, library):
        if hashlib.sha256(Path(library).read_bytes()).hexdigest() != SO_SHA256:
            raise ValueError("Unknown 1FTunnel ARM64 layout")
        super().__init__(library)

    def result(self, value):
        self.uc.reg_write(UC_ARM64_REG_X0, value)
        self.uc.reg_write(UC_ARM64_REG_PC, self.uc.reg_read(UC_ARM64_REG_X30))

    def vector(self, data):
        ptr = self.alloc(data or b"\0")
        return self.alloc(struct.pack("<3Q", ptr, ptr + len(data), ptr + len(data)))

    def data(self, vec):
        start, end = struct.unpack("<2Q", self.read(vec, 16))
        if end < start or end - start > 5 * 1024 * 1024:
            raise ValueError("Native vector exceeds bound")
        return self.read(start, end - start)

    def writevec(self, vec, data):
        ptr = self.alloc(data or b"\0")
        self.uc.mem_write(vec, struct.pack("<3Q", ptr, ptr + len(data), ptr + len(data)))

    def _step(self, uc, address, size, extra):
        if address not in self.image.plt and address != 0x6a7ec:
            return
        try:
            a, b, c, d = [self.reg(i) for i in range(4)]
            if address == 0x6a7ec:
                self.writevec(d, hmac.digest(self.data(b), self.data(c), "sha256"))
                self.result(1)
                return
            name = self.image.plt.get(address, "")
            if name == "_Znwm":
                if a > 5 * 1024 * 1024:
                    raise ValueError("Native allocation exceeds bound")
                self.result(self.alloc(a))
            elif name == "_ZdlPv":
                self.result(0)
            elif name in ("memmove", "memcpy", "__memcpy_chk"):
                if c > 5 * 1024 * 1024 or (name == "__memcpy_chk" and c > d):
                    raise ValueError("Native copy exceeds bound")
                uc.mem_write(a, self.read(b, c))
                self.result(a)
            else:
                super()._step(uc, address, size, extra)
        except Exception as error:
            self.error = error
            uc.emu_stop()

    def kdf(self, version, slot, salt, aad, password=b""):
        out = self.vector(b"")
        ok = self.call(0x6432c, 0, version, slot, self.vector(salt), self.vector(aad),
                       self.vector(password), out, limit=5_000_000)
        if not ok:
            raise ValueError("Native KDF rejected input")
        return self.data(out)
