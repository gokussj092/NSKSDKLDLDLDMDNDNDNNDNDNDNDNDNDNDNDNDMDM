"""Bounded original build-60 ARM64 primitives; no JNI, Android or external services."""
from __future__ import annotations
import hashlib
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/apk_analysis'))
from arm64_function import Arm64Function
from unicorn.arm64_const import UC_ARM64_REG_PC,UC_ARM64_REG_X0,UC_ARM64_REG_X30

NATIVE_SHA256='3c6ad15db5484317c557ae1c1935b102f264c86420552cd53d449045a09ca8c5'


class NativePrimitives(Arm64Function):
    """Allow only bounded allocation/string helpers and named offline primitives."""
    def __init__(self,path):
        if hashlib.sha256(Path(path).read_bytes()).hexdigest()!=NATIVE_SHA256:
            raise ValueError('Unsupported native build')
        super().__init__(path)

    def _step(self,uc,address,size,user):
        name=self.image.plt.get(address)
        try:
            a,b,n=self.reg(0),self.reg(1),self.reg(2)
            if name in ('malloc','calloc'):
                length=a if name=='malloc' else a*b
                if not 0<=length<=8*1024*1024:raise ValueError('Allocation limit')
                uc.reg_write(UC_ARM64_REG_X0,self.alloc(max(1,length)))
            elif name=='free':pass
            elif name=='strncmp':
                if n>8*1024*1024:raise ValueError('String limit')
                left,right=self.read(a,n).split(b'\0',1)[0],self.read(b,n).split(b'\0',1)[0]
                uc.reg_write(UC_ARM64_REG_X0,((left>right)-(left<right))&0xffffffffffffffff)
            elif name in ('threefishDecrypt256','threefishEncrypt256','threefishSetKey'):
                uc.reg_write(UC_ARM64_REG_PC,self.image.names[name][0]);return
            else:
                super()._step(uc,address,size,user);return
            uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_X30))
        except Exception as exc:
            self.error=exc;uc.emu_stop()

    def xxtea(self,raw,key):
        source=self.alloc(raw+b'\0');material=self.alloc(key[:16].ljust(16,b'\0'));length=self.alloc(8)
        result=self.call(0x4c0d68,source,len(raw),material,length)
        n=struct.unpack('<Q',self.read(length,8))[0]
        if not result or n>len(raw):raise ValueError('Invalid native XXTEA output')
        return self.read(result,n)

    def threefish(self,raw,key):
        if len(raw)%32 or len(key)!=32:raise ValueError('Invalid native Threefish input')
        material=self.alloc(key);out=bytearray()
        for offset in range(0,len(raw),32):
            schedule=self.alloc(0x200);tweak=self.alloc(struct.pack('<QQ',offset//32,(offset//32)*64))
            self.call(0x4c408c,schedule,256,material,tweak)
            source=self.alloc(raw[offset:offset+32]);target=self.alloc(32)
            self.call(0x4c4350,schedule,source,target)
            out.extend(self.read(target,32))
        return bytes(out)
