#!/usr/bin/env python3
"""Execute four bounded original JNI wrappers with modeled string/Java calls.

No JVM/Android startup, provider initialization, network, or OS calls. Confirms
class, method and fixed key argument actually passed by each ARM64 wrapper.
Crypto is Java-side in this APK and is checked separately by the JDK oracle.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
from arm64_function import Arm64Function
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X30, UC_ARM64_REG_PC

NATIVE_SHA256 = "4334eee1a8743bb88aeb5effcf842807a67355210161899652b4d7513260c3dc"
WRAPPERS = {"Jenc":0x26268, "Jdec":0x2635c, "Fenc":0x26450, "Fdec":0x26554}


class NativeWrappers(Arm64Function):
    def __init__(self, path):
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != NATIVE_SHA256:
            raise ValueError("Unsupported native build")
        super().__init__(path)
        self.table=self.alloc(0x800)
        self.env=self.alloc(struct.pack("<Q",self.table))
        self.stubs={}
        for i,offset in enumerate((0x30,0x388,0x538,0x548,0x550,0xb8)):
            address=self.STOP+0x100+4*i
            self.stubs[address]=offset
            self.uc.mem_write(self.table+offset,struct.pack("<Q",address))
        self.classes={};self.methods={};self.calls=[]

    def cstring(self,address):
        value=bytearray()
        for i in range(4096):
            c=self.read(address+i,1)
            if c==b"\0":return value.decode("utf-8")
            value.extend(c)
        raise ValueError("Unterminated native string")

    def _step(self,uc,address,size,user):
        offset=self.stubs.get(address)
        java_call=self.image.plt.get(address)=="_ZN7_JNIEnv22CallStaticObjectMethodEP7_jclassP10_jmethodIDz"
        if offset is None and not java_call:
            super()._step(uc,address,size,user);return
        try:
            value=0
            if offset==0x30:
                value=self.alloc(16);self.classes[value]=self.cstring(self.reg(1))
            elif offset==0x388:
                value=self.alloc(16)
                self.methods[value]=(self.cstring(self.reg(2)),self.cstring(self.reg(3)))
            elif offset in (0x538,0x548):
                value=self.reg(1)
            elif java_call:
                self.calls.append((self.classes[self.reg(1)],self.methods[self.reg(2)],
                                   self.cstring(self.reg(3)),self.cstring(self.reg(4))))
                value=self.alloc(b"modeled Java result\0")
            uc.reg_write(UC_ARM64_REG_X0,value)
            uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_X30))
        except Exception as exc:
            self.error=exc;uc.emu_stop()

    def verify(self):
        expected_keys={
            "J":"AESCBCcrptor;Java/com/jztunnel_vpn_libandroid.so_:crypto_NativeCrypto/Fdecrypt/(Ljava/lang/String;Ljava/lang/Strin",
            "F":"(Ljava/lang/String;Ljava/lang/String)https://;t.me/noobdev24",
        }
        for name,address in WRAPPERS.items():
            self.calls=[]
            self.call(address,self.env,0,self.alloc(b"synthetic argument\0"),limit=10000)
            if self.calls != [("com/noobdev/vpn/Utilities/crypto/" + ("AESCBCEncryptor" if name[0]=="J" else "AESCFBEncryptor"),
                               ("encrypt" if name.endswith("enc") else "decrypt",
                                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"),
                               "synthetic argument",expected_keys[name[0]])]:
                raise ValueError("Native wrapper arguments differ from the documented recipe")
        return {"nativeWrappersEqual":len(WRAPPERS),"cryptoExecutedByNative":False}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("library",type=Path);a=p.parse_args()
    print(json.dumps(NativeWrappers(a.library).verify()))


if __name__=="__main__":main()
