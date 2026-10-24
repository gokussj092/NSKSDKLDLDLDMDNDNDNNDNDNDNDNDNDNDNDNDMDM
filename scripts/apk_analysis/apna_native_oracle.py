#!/usr/bin/env python3
"""Run only APNA's original isolated XOR primitive with modeled C++ strings.

No JNI/signature checks/Android startup, network or OS calls are executed.
The basic_string copy constructor and delete are modeled at their PLT entries.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from arm64_function import Arm64Function
from unicorn.arm64_const import UC_ARM64_REG_X8,UC_ARM64_REG_X30,UC_ARM64_REG_PC

NATIVE_SHA256 = "f5198b3d5efa4bd446a18e4c12357ed8dcff3df072b62596526cc4152225bd45"
KEY = b"4%PdXch>fkP]"
XOR_ADDRESS = 0x1466d0
COPY = "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1ERKS5_"


class NativeXor(Arm64Function):
    def __init__(self,path):
        if hashlib.sha256(Path(path).read_bytes()).hexdigest()!=NATIVE_SHA256:
            raise ValueError('Unsupported APNA native build')
        super().__init__(path)

    def string(self,address):
        obj=self.read(address,24)
        if obj[0]&1:
            size,pointer=struct.unpack_from('<QQ',obj,8)
            if size>8*1024*1024:raise ValueError('String too large')
            return self.read(pointer,size)
        return obj[1:1+(obj[0]>>1)]

    def put_string(self,address,data):
        if len(data)<=22:obj=bytes([len(data)*2])+data+b'\0';obj=obj.ljust(24,b'\0')
        else:
            pointer=self.alloc(data+b'\0')
            obj=struct.pack('<QQQ',((len(data)+16)&~15)|1,len(data),pointer)
        self.uc.mem_write(address,obj)

    def _step(self,uc,address,size,user):
        name=self.image.plt.get(address)
        if name not in (COPY,'_ZdlPv'):
            super()._step(uc,address,size,user);return
        try:
            if name==COPY:self.put_string(self.reg(0),self.string(self.reg(1)))
            uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_X30))
        except Exception as exc:self.error=exc;uc.emu_stop()

    def transform(self,data):
        source=self.alloc(24);target=self.alloc(24)
        self.put_string(source,data)
        self.uc.reg_write(UC_ARM64_REG_X8,target)
        self.call(XOR_ADDRESS,source,limit=2_000_000)
        return self.string(target)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('native',type=Path);args=parser.parse_args()
    vectors=[b'',b'{}',bytes(range(1,23)),bytes(range(1,100)),b'{"friendly_name":"native test","tweak_password":"demo"}']
    for raw in vectors:
        native=NativeXor(args.native)
        expected=bytes(v^KEY[i%len(KEY)] for i,v in enumerate(raw))
        assert native.transform(raw)==expected,'Original native XOR differs'
    print(json.dumps({'originalArm64XorCases':len(vectors),'equal':True}))


if __name__=='__main__':main()
