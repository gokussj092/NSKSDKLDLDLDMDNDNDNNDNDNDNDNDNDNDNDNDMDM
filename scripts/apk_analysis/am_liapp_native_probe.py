#!/usr/bin/env python3
"""AM-63-only bounded LIAPP checkpoint oracle, using a virtual file/context model.

Never execute this ELF on the host. No real JNI, OS calls or network are exposed.
Only the two hash-pinned APKs are readable. Empty /proc streams, fixed process
IDs and virtual paths model part of bootstrap; they do not emulate Android or
prove that the entire protected app starts. Original LCG, inflater, metadata
checks and optional AES execute. Byte/string/copy/CRC helpers are accelerated.
Default stops at 0x803b4 after the original metadata relation check. --buffers
stops at 0x829e8 before the later environment/integrity comparisons. Its buffers
are research inputs, not a DEX or a catalog reader. Do not enable the provider.
"""
from pathlib import Path
import argparse, hashlib, json, struct, io, re, zlib
from am_liapp_metadata import APK_SHA256, METADATA_SHA256, MAX_APK_BYTES, recover
from liapp_wrapper import CORE_SHA256

SPLIT_SHA256 = 'a15dfef0f285bb4283af029187561a65150f509b1af15974709070436ffafddc'

def checked_bytes(path, expected, limit):
    with path.open('rb') as stream: raw=stream.read(limit+1)
    if len(raw)>limit or hashlib.sha256(raw).hexdigest()!=expected:
        raise ValueError('Unsupported input build: '+path.name)
    return raw
from arm64_function import Arm64Function
from unicorn.arm64_const import UC_ARM64_REG_PC,UC_ARM64_REG_X0,UC_ARM64_REG_X30

class Probe(Arm64Function):
    def __init__(self, core, base_apk, arm64_apk, output=None, buffers=False):
        checked_bytes(core,CORE_SHA256,2*1024*1024)
        self.payload=checked_bytes(base_apk,APK_SHA256,MAX_APK_BYTES)
        split=checked_bytes(arm64_apk,SPLIT_SHA256,MAX_APK_BYTES)
        super().__init__(core)
        if hashlib.sha256(self.image.data).hexdigest()!=CORE_SHA256:
            raise ValueError('Native core changed during load')
        self.output=output;self.buffers=buffers;self.metadata=None;self.metadata_length=None;self.buffer_report={}
        self.allocations={}
        self.virtual={b'/input/base.apk':self.payload,b'/input/split_config.arm64_v8a.apk':split}
        self.fds={0:io.BytesIO(self.payload)}
        self.fdpaths={0:b'/input/base.apk'}
        self.trace=[]
        self.uc.mem_write(0xa5f80,struct.pack('<5I',0xa6038691,0xb3167321,0xc5292045,0xd6162568,0x11308681))
        self.pkg=self.alloc(b'app.vpn.amtunnellite\0')
        self.uc.mem_write(0xa3f38,struct.pack('<Q',self.alloc(struct.pack('<Q',self.pkg))))
        self.path=self.alloc(b'/input/base.apk\0')
        self.uc.mem_write(0xa4128,struct.pack('<Q',self.pkg))
        for off,value in {0x18:b'/input/base.apk',0x20:b'/data/user/0/app.vpn.amtunnellite',0x10:b'/input/lib/arm64',0x48:b'arm64-v8a',0x50:b'/input/split_config.arm64_v8a.apk',0x5c8:b'/output/cache',0x5d0:b'/output/main',0x5d8:b'/output/secondary',0x40:b'arm64-v8a',0x30:b'2.1.0',0x58:b'/input/split_config.arm64_v8a.apk'}.items():
            self.uc.mem_write(0xa4128+off,struct.pack('<Q',self.alloc(value+b'\0')))
        self.uc.mem_write(0xa4128+0x8a4,struct.pack('<I',63))
        self.uc.mem_write(0xa4128+0x8a4+8,struct.pack('<I',63))
        self.uc.mem_write(0xa4878,b'assets/.efuyxx.dex\0')
        self.errno=self.alloc(8)

    def save(self,name,data):
        if self.output is None:return
        target=self.output/name
        with target.open('xb') as stream:stream.write(data)
        target.chmod(0o600)
    def alloc(self,data):
        n=data if isinstance(data,int) else len(data)
        if n>16*1024*1024:raise ValueError('Allocation bound')
        address=super().alloc(data)
        self.allocations[address]=n
        return address
    def string(self,p):
        out=bytearray()
        for i in range(3):
            chunk=self.read(p,min(8192-len(out),4096-(p&4095)))
            if b'\0' in chunk:return bytes(out)+chunk.split(b'\0',1)[0]
            out.extend(chunk);p+=len(chunk)
        raise ValueError('Unterminated virtual string')
    def result(self,v):
        self.uc.reg_write(UC_ARM64_REG_X0,v&((1<<64)-1))
        self.uc.reg_write(UC_ARM64_REG_PC,self.uc.reg_read(UC_ARM64_REG_X30))
    def _step(self,uc,address,size,extra):
        if address not in {0x10758,0x107b8,0x107d4,0x10838,0x10870,0x108c4,0x108e8,0x10994,0x7f820,0x7faf8,0x802dc,0x803a8,0x803b4,0x829e8} and address not in self.image.plt:return
        try:
            if address==0x829e8:
                buffers={}
                for label,offset in [('primary',0x5b8),('expanded',0x5c0)]:
                    ptr=struct.unpack('<Q',self.read(0xa4128+offset,8))[0]
                    n=self.allocations[ptr]
                    raw=self.read(ptr,n)
                    self.save(label+'.bin',raw)
                    buffers[label]={'bytes':n,'sha256':hashlib.sha256(raw).hexdigest()}
                for ptr,n in self.allocations.items():
                    if n>0:self.save(hex(ptr)+'.bin',self.read(ptr,n))
                self.save('globals.bin',self.read(0xa4120,0x1d00))
                self.save('allocations.json',json.dumps(self.allocations).encode())
                self.buffer_report=buffers
                uc.reg_write(UC_ARM64_REG_PC,self.STOP);return
            a,b,c,d=[self.reg(i) for i in range(4)]
            if address==0x803b4:
                self.metadata=self.read(self.reg(22)-8,self.metadata_length)
                if hashlib.sha256(self.metadata).hexdigest()!=METADATA_SHA256:raise ValueError('Unexpected native metadata')
                self.save('metadata.bin',self.metadata)
                if not self.buffers:uc.reg_write(UC_ARM64_REG_PC,self.STOP);return
            if address==0x803a8:raise ValueError('Metadata relation check failed')
            if address==0x802dc:
                length=struct.unpack('<I',self.read(self.reg(21),4))[0]
                self.metadata_length=length
                if not 24<=length<=8192:raise ValueError('Decoded metadata length bound')
            if address in (0x107d4,0x10838):
                if not a or not b:self.result(-1);return
                left,right=self.string(a),self.string(b)
                if address==0x10838:left,right=left[:c],right[:c]
                self.result((left>right)-(left<right));return
            if address in (0x10870,0x108c4,0x108e8):
                raw=self.string(a)
                needle=self.string(b) if address==0x10870 else bytes([b&255])
                if address!=0x10870 and needle==b'\0':self.result(a+len(raw));return
                at=raw.rfind(needle) if address==0x108e8 else raw.find(needle)
                self.result(a+at if at>=0 else 0);return
            if address==0x10758:
                if c>16*1024*1024:raise ValueError('Copy bound')
                uc.mem_write(a,self.read(b,c));self.result(a);return
            if address==0x107b8 and not a:raise ValueError('Null native string')
            if address==0x107b8:self.result(len(self.string(a)));return
            if address==0x10994:
                if b>16*1024*1024:raise ValueError('CRC bound')
                self.result(zlib.crc32(self.read(a,b)));return
            name=self.image.plt.get(address)
            if name:
                if name=='sprintf':
                    import re
                    fmt=self.string(b).decode('latin-1')
                    args=[]
                    for i,spec in enumerate(re.findall(r'%(?:[0-9]+\.[0-9]+|[0-9]+)?[sdxXu]',fmt)):
                        value=self.reg(i+2)
                        if spec.endswith('s'):value=self.string(value).decode('latin-1')
                        elif spec.endswith('d') and value&0x80000000:value=(value&0xffffffff)-(1<<32)
                        args.append(value)
                    pyfmt=fmt.replace('%u','%d')
                    out=(pyfmt%tuple(args)).encode('latin-1')
                    if len(out)>8192:raise ValueError('Formatted string bound')
                    uc.mem_write(a,out+b'\0');self.result(len(out));return
                if name=='malloc':self.result(self.alloc(a));return
                if name=='calloc':
                    if a*b>16*1024*1024:raise ValueError('Calloc bound')
                    self.result(self.alloc(a*b));return
                if name=='realloc':
                    if a:raise ValueError('Realloc existing buffer requires size tracking')
                    self.result(self.alloc(b));return
                if name=='clock_gettime':uc.mem_write(b,struct.pack('<qq',123,0));self.result(0);return
                if name=='free':self.result(0);return
                if name=='fopen':
                    path=self.string(a)
                    if path not in self.virtual and not path.startswith(b'/proc/'):self.result(0);return
                    fd=max(self.fds)+1;self.fds[fd]=io.BytesIO(self.virtual.get(path,b''));self.fdpaths[fd]=path;self.result(fd);return
                if name=='fileno':self.result(a);return
                if name=='fclose':self.result(0);return
                if name=='fgets':
                    data=self.fds[c].readline(b-1)
                    if data:uc.mem_write(a,data+b'\0')
                    self.result(a if data else 0);return
                if name=='openat':
                    path=self.string(b)
                    if path not in self.virtual:
                        if not (c&0x40) or not path.startswith(b'/output/'):self.result(-1);return
                        self.virtual[path]=b''
                    fd=max(self.fds)+1;self.fds[fd]=io.BytesIO(self.virtual[path]);self.fdpaths[fd]=path;self.result(fd);return
                if name in ('lseek','lseek64'):
                    off=b if b<1<<63 else b-(1<<64)
                    self.result(self.fds[a].seek(off,c));return
                if name=='read':
                    if c>16*1024*1024:raise ValueError('Read bound')
                    data=self.fds[a].read(c);uc.mem_write(b,data);self.result(len(data));return
                if name=='write':
                    if c>16*1024*1024:raise ValueError('Write bound')
                    raw=self.read(b,c);self.fds[a].write(raw)
                    if len(raw)>128:self.save('write-'+str(a)+'.bin',raw)
                    self.result(c);return
                if name=='close':self.result(0);return
                if name in ('lstat','stat'):
                    if self.string(a) not in self.virtual:self.result(-1);return
                    uc.mem_write(b,bytes(128));uc.mem_write(b+0x30,struct.pack('<Q',len(self.virtual[self.string(a)])));self.result(0);return
                if name=='readlink':
                    path=self.string(a)
                    fd=int(path.rsplit(b'/',1)[1])
                    data=self.fdpaths[fd];uc.mem_write(b,data[:c]);self.result(min(c,len(data)));return
                if name in ('getpid','gettid'):self.result(1000);return
                if name=='__errno':self.result(self.errno);return
                if name in ('strtoul','strtoull'):
                    import re
                    raw=self.string(a);base=c or (16 if raw.lower().startswith(b'0x') else 10)
                    pat=rb'[0-9a-fA-F]+' if base==16 else rb'[0-9]+'
                    prefix=re.match(pat,raw)
                    end=len(prefix[0]) if prefix else 0
                    if b:uc.mem_write(b,struct.pack('<Q',a+end))
                    self.result(int(prefix[0],base) if prefix else 0);return
                if name=='strlen':self.result(len(self.string(a)));return
            if address in (0x7f820,0x7faf8):self.trace.append((hex(address),hex(a),hex(self.reg(3)),hex(self.reg(1))))
            super()._step(uc,address,size,extra)
        except Exception as exc:self.error=exc;uc.emu_stop()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('core',type=Path)
    parser.add_argument('base_apk',type=Path)
    parser.add_argument('arm64_apk',type=Path)
    parser.add_argument('--output',type=Path,help='New private directory for optional checkpoint files')
    parser.add_argument('--buffers',action='store_true',help='Experimental later checkpoint; never emits a recovered DEX')
    args=parser.parse_args()
    if args.output and args.output.exists():parser.error('Output directory already exists')
    _,plain=recover(args.base_apk)
    probe=Probe(args.core,args.base_apk,args.arm64_apk,args.output,args.buffers)
    if args.output:args.output.mkdir(parents=True,mode=0o700)
    probe.call(0x7e018,probe.path,1,limit=30_000_000)
    if probe.metadata!=plain:raise ValueError('Full native/Python metadata mismatch')
    report={'metadataBytes':len(plain),'metadataSha256':METADATA_SHA256,
            'fullNativeMetadataEqual':True,'nativeLcgExecuted':True,
            'modeledEnvironment':True,'androidExecuted':False,
            'buffers':probe.buffer_report,'dexRecovered':False,'catalogDecoded':False}
    probe.save('report.json',json.dumps(report,indent=2).encode())
    print(json.dumps(report))

if __name__=='__main__':main()
