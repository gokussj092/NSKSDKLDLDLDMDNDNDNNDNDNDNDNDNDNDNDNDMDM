"""Bounded, network-free ARM64 oracle for the app's local string-format JNI codec.

Never loads JNI_OnLoad, app lifecycle, VPN code, sockets, files or authentication
hooks. Only direct documented local format functions and pure memory/libc stubs.
Unknown imports/JNI methods stop execution. Private input/output stay in files.
"""
from pathlib import Path
import argparse,struct,json,hashlib
from elftools.elf.elffile import ELFFile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *

REGS=[globals()[f'UC_ARM64_REG_X{i}']for i in range(29)]+[UC_ARM64_REG_FP,UC_ARM64_REG_LR]

class Oracle:
    def __init__(self,path):
        assert hashlib.sha256(Path(path).read_bytes()).hexdigest()=="16f41ddccf24ffb14ddf6719a9df94cae60425a92d04097475770a407791a2e0",'Unreviewed native binary'
        self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        self.u.mem_map(0,0x80000)
        self.u.mem_map(0x1000000,0x2000000)
        self.heap=0x1000000
        self.u.mem_map(0x4000000,0x100000)
        self.u.mem_map(0x5000000,0x10000)
        self.u.mem_map(0x6000000,0x10000)
        self.u.mem_map(0x7000000,0x10000)
        self.stub=0x7000000
        self.functions={}
        self.calls=[]
        self.sizes={}
        self.arrays={}
        self.classes={}
        self.methods={}
        with Path(path).open('rb')as f:
            e=ELFFile(f)
            for seg in e.iter_segments():
                if seg['p_type']=='PT_LOAD':self.u.mem_write(seg['p_vaddr'],seg.data())
            for sec in e.iter_sections():
                if sec['sh_type']!='SHT_RELA':continue
                syms=e.get_section(sec['sh_link'])
                for r in sec.iter_relocations():
                    sym=syms.get_symbol(r['r_info_sym'])if r['r_info_sym']else None
                    if r['r_info_type']==1027:value=r['r_addend']
                    elif sym and sym['st_shndx']!='SHN_UNDEF':value=sym['st_value']+r['r_addend']
                    elif sym:
                        value=self.stub;self.stub+=4;self.functions[value]=('libc',sym.name)
                    else:continue
                    self.u.mem_write(r['r_offset'],struct.pack('<Q',value))
        self.env=0x5000000;table=self.env+0x1000
        self.u.mem_write(self.env,struct.pack('<Q',table))
        for i in range(240):
            p=self.stub;self.stub+=4;self.functions[p]=('jni',i)
            self.u.mem_write(table+8*i,struct.pack('<Q',p))
        self.u.reg_write(UC_ARM64_REG_TPIDR_EL0,0x6000000)
        self.u.hook_add(UC_HOOK_CODE,self.hook)

    def reg(self,n):return self.u.reg_read(REGS[n])
    def cstr(self,p):
        if not p:return b''
        out=bytearray()
        for n in range(0,4*1024*1024,256):
            part=bytes(self.u.mem_read(p+n,256));stop=part.find(b'\0')
            if stop>=0:return bytes(out)+part[:stop]
            out.extend(part)
        raise ValueError('CString bound')
    def alloc(self,size,data=None):
        assert 0<=size<=4*1024*1024
        p=self.heap;self.heap+=(size+31)&~15
        assert self.heap<0x3000000
        self.sizes[p]=size
        if data:self.u.mem_write(p,bytes(data))
        return p
    def hook(self,u,pc,size,data):
        if pc not in self.functions:return
        kind,name=self.functions[pc];a=[self.reg(i)for i in range(8)];result=0
        self.calls.append((kind,name))
        if kind=='jni':
            if name==169:result=a[1] # GetStringUTFChars
            elif name==168:result=len(self.cstr(a[1]))
            elif name==167:result=a[1] # NewStringUTF
            elif name==170:pass # ReleaseStringUTFChars
            elif name in (228,15):result=0 # ExceptionCheck / ExceptionOccurred
            elif name in (17,23):pass # ExceptionClear / DeleteLocalRef
            elif name==6:
                cls=self.cstr(a[1]).decode('ascii')
                if cls!='java/lang/String':raise RuntimeError(f'Unsupported local class {cls}')
                result=self.alloc(16);self.classes[result]=cls
            elif name==33:
                method=self.cstr(a[2]).decode('ascii');sig=self.cstr(a[3]).decode('ascii')
                if self.classes.get(a[1])!='java/lang/String' or method!='<init>' or sig!='([BLjava/lang/String;)V':
                    raise RuntimeError(f'Unsupported local method {method} {sig}')
                result=self.alloc(16);self.methods[result]=(method,sig)
            elif name==176:
                result=self.alloc(a[1]);self.arrays[result]=a[1]
            elif name==208:
                assert a[1]in self.arrays and a[2]+a[3]<=self.arrays[a[1]]
                u.mem_write(a[1]+a[2],bytes(u.mem_read(a[4],a[3])))
            elif name==171:result=self.arrays[a[1]]
            elif name in (28,29):
                assert a[2]in self.methods
                if name==28:array,charset=a[3:5]
                else:
                    stack,gr_top,vr_top,gr_offs,vr_offs=struct.unpack('<QQQii',bytes(u.mem_read(a[3],32)))
                    args=bytes(u.mem_read(gr_top+gr_offs,16))if gr_offs<0 else bytes(u.mem_read(stack,16))
                    array,charset=struct.unpack('<QQ',args)
                encoding=self.cstr(charset).decode('ascii').lower()
                assert encoding in ('utf-8','utf8') and array in self.arrays
                raw=bytes(u.mem_read(array,self.arrays[array]))
                text=raw.decode('utf-8',errors='replace').encode('utf-8')
                result=self.alloc(len(text)+1,text+b'\0')
            else:raise RuntimeError(f'Unimplemented JNI index {name}')
        elif name in ('strlen','__strlen_chk'):result=len(self.cstr(a[0]))
        elif name=='isalnum':result=int(48<=a[0]<=57 or 65<=a[0]<=90 or 97<=a[0]<=122)
        elif name in ('malloc','_Znwm','_Znam'):result=self.alloc(a[0])
        elif name=='calloc':result=self.alloc(a[0]*a[1])
        elif name=='realloc':
            result=self.alloc(a[1]);n=min(self.sizes.get(a[0],0),a[1])
            if n:u.mem_write(result,bytes(u.mem_read(a[0],n)))
        elif name in ('free','_ZdlPv','_ZdaPv'):pass
        elif name in ('memcpy','memmove','__memcpy_chk','__memmove_chk'):
            u.mem_write(a[0],bytes(u.mem_read(a[1],a[2])));result=a[0]
        elif name in ('memset','__memset_chk'):
            u.mem_write(a[0],bytes([a[1]&255])*a[2]);result=a[0]
        elif name in ('strcmp','strncmp'):
            left=self.cstr(a[0]);right=self.cstr(a[1])
            if name=='strncmp':left=left[:a[2]];right=right[:a[2]]
            result=(left>right)-(left<right)
        elif name in ('strchr','__strchr_chk'):
            at=self.cstr(a[0]).find(bytes([a[1]&255]));result=a[0]+at if at>=0 else 0
        else:raise RuntimeError(f'Unimplemented pure import {name}')
        u.reg_write(UC_ARM64_REG_X0,result&0xffffffffffffffff)
        u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
    def run(self,entry,value,mode,algorithm):
        ptr=self.alloc(len(value)+1,value+b'\0')
        for i,v in enumerate((self.env,0,0,ptr,mode,algorithm)):self.u.reg_write(REGS[i],v)
        self.u.reg_write(UC_ARM64_REG_SP,0x40ff000)
        self.u.reg_write(UC_ARM64_REG_LR,0x700f000)
        self.u.emu_start(entry,0x700f000,timeout=20_000_000,count=50_000_000)
        assert self.u.reg_read(UC_ARM64_REG_PC)==0x700f000,'Oracle instruction/time bound'
        return self.cstr(self.u.reg_read(UC_ARM64_REG_X0))

def main():
    p=argparse.ArgumentParser();p.add_argument('library',type=Path);p.add_argument('input',type=Path)
    p.add_argument('--mode',type=int,default=1);p.add_argument('--algorithm',type=int,default=3)
    p.add_argument('--entry',type=lambda s:int(s,0),default=0xfe6c);p.add_argument('--output',type=Path)
    a=p.parse_args();oracle=Oracle(a.library)
    try:
        result=oracle.run(a.entry,a.input.read_bytes(),a.mode,a.algorithm)
        if a.output:
            assert not a.output.resolve().is_relative_to(Path(__file__).resolve().parents[4]),'Private output must stay outside Git'
            a.output.write_bytes(result);a.output.chmod(0o600)
        print(json.dumps({'bytes':len(result),'calls':oracle.calls[-20:]}))
    except Exception as exc:
        print(json.dumps({'error':str(exc),'pc':hex(oracle.u.reg_read(UC_ARM64_REG_PC)),'calls':oracle.calls[-20:]}));raise
if __name__=='__main__':main()
