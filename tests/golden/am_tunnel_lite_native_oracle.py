"""Bounded original PUtils XOR only; no JNI, app startup, signature checks or OS."""
from __future__ import annotations
import argparse,base64,hashlib,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/apk_analysis'))
from arm64_function import Arm64Function
from unicorn.arm64_const import UC_ARM64_REG_PC,UC_ARM64_REG_X0,UC_ARM64_REG_X8,UC_ARM64_REG_X30
NATIVE_SHA256='a0e7c704dbf8bde1ee5e05d230a0232e0c5ea3f75b4be01d6519993cfdf93890'
COPY='_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1ERKS5_'


class NativeFields(Arm64Function):
    def __init__(self,path):
        if hashlib.sha256(Path(path).read_bytes()).hexdigest()!=NATIVE_SHA256:raise ValueError('Unsupported native build')
        super().__init__(path)

    def string(self,address):
        flag=self.read(address,1)[0]
        if flag&1:
            size,ptr=struct.unpack('<QQ',self.read(address+8,16))
            if size>1024*1024:raise ValueError('String exceeds limit')
            return self.read(ptr,size)
        return self.read(address+1,flag>>1)

    def put_string(self,address,data):
        if len(data)<23:value=bytes([len(data)<<1])+data+b'\0'*(23-len(data))
        else:value=struct.pack('<QQQ',((len(data)+16)&~15)|1,len(data),self.alloc(data+b'\0'))
        self.uc.mem_write(address,value)

    def _step(self,uc,address,size,user):
        name=self.image.plt.get(address)
        try:
            if name==COPY:
                dest=self.reg(0);self.put_string(dest,self.string(self.reg(1)));uc.reg_write(UC_ARM64_REG_X0,dest)
            elif name=='_ZdlPv':pass
            else:super()._step(uc,address,size,user);return
            uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_X30))
        except Exception as exc:self.error=exc;uc.emu_stop()

    def xor(self,raw):
        source=self.alloc(24);result=self.alloc(24);self.put_string(source,raw)
        self.uc.reg_write(UC_ARM64_REG_X8,result);self.call(0x1466d4,source)
        return self.string(result)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('native',type=Path);a=p.parse_args()
    fixture=json.loads(Path(__file__).with_name('am_tunnel_lite_vectors.json').read_text())
    for vector in fixture['fields']:
        result=NativeFields(a.native).xor(bytes.fromhex(vector['cipher']))
        if result!=base64.b64decode(vector['modifiedUtf8Base64']):raise ValueError('Original native XOR differs from JDK')
    print(json.dumps({'nativeFieldCasesEqual':len(fixture['fields']),'catalogDecoded':False}))

if __name__=='__main__':main()
