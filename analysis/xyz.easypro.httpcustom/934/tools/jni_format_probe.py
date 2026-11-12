"""Offline JNI registration/format probe. No Android lifecycle or network I/O.

Models only in-memory JNI objects and libc. Unknown calls halt the probe.
Adapted from the owner retained build-914 jni_probe.py, never loaded with pickle.
"""
import argparse,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT/'scripts/apk_analysis'))
from arm64_function import Arm64Function
from unicorn import UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X30,UC_ARM64_REG_PC,UC_ARM64_REG_X8

class Probe(Arm64Function):
    STACK=0x10000000;TLS=0x11000000;HEAP=0x12000000;STOP=0x14000000
    def __init__(self,path):
        super().__init__(path)
        syms=self.image.elf.get_section_by_name('.dynsym');plt={n:a for a,n in self.image.plt.items()}
        for r in self.image.relocations:
            if r['r_info_type']==257:
                name=syms.get_symbol(r['r_info_sym']).name
                if name not in plt:plt[name]=0x500a000+16*len(plt);self.image.plt[plt[name]]=name
                self.uc.mem_write(r['r_offset'],struct.pack('<Q',(plt[name]+r['r_addend'])&((1<<64)-1)))
        self.objects={};self.nextobj=0x90000000;self.logs=[];self.registrations=[];self.thread_values={}
        self.uc.mem_map(0x5000000,0x10000)
        # Never issue host syscalls; unavailable Android files return ENOENT.
        self.uc.hook_add(UC_HOOK_INTR,lambda u,i,d:u.reg_write(UC_ARM64_REG_X0,(-2)&((1<<64)-1)))
        self.env=self.alloc(struct.pack('<Q',self.alloc(b''.join(struct.pack('<Q',0x5000000+16*i) for i in range(240)))))
        self.vm=self.alloc(struct.pack('<Q',self.alloc(b''.join(struct.pack('<Q',0x5008000+16*i) for i in range(8)))))
        self.observers[0x5008060]=lambda e:(e.uc.mem_write(e.reg(1),struct.pack('<Q',e.env)),e.finish())
        for i in range(240):self.observers[0x5000000+16*i]=lambda e,i=i:self.jni(i)
        self.uc.hook_del(self.step_hook)
        for a,name in self.image.plt.copy().items():
            if name in ('strlen','strcmp','memcmp','lrand48','__system_property_get','getauxval','pthread_mutex_lock','pthread_mutex_unlock','malloc','calloc','free','__strncpy_chk','prctl','pthread_once','pthread_key_create','pthread_getspecific','pthread_setspecific','pthread_key_delete','dl_iterate_phdr','opendir','getpid','getuid','__errno','readlink','nanosleep'):
                del self.image.plt[a];self.observers[a]=lambda e,name=name:self.imported(name)
        for a in set(self.image.plt)|set(self.observers):self.uc.hook_add(UC_HOOK_CODE,self._step,begin=a,end=a)
        patches_file=Path(path).with_suffix('.preambles.json')
        if patches_file.exists():
            for a,target in json.loads(patches_file.read_text()).items():
                a=int(a);self.observers[a]=lambda e,t=target:e.uc.reg_write(UC_ARM64_REG_PC,t)
                self.uc.hook_add(UC_HOOK_CODE,self._step,begin=a,end=a)
    def finish(self,value=0):
        self.uc.reg_write(UC_ARM64_REG_X0,value&((1<<64)-1));self.uc.reg_write(UC_ARM64_REG_PC,self.uc.reg_read(UC_ARM64_REG_X30))
    def obj(self,value):self.nextobj+=8;self.objects[self.nextobj]=value;return self.nextobj
    def cstr(self,p):
        if not p:return ''
        result=bytearray()
        for i in range(20000):
            b=self.read(p+i,1)
            if b==b'\0':return result.decode('utf8',errors='replace')
            result.extend(b)
        raise ValueError('CString bound')
    def imported(self,name):
        a=[self.reg(i) for i in range(4)];v=0
        if name=='nanosleep':
            self.sleep_calls=getattr(self,'sleep_calls',0)+1
            if self.sleep_calls>3:raise ValueError('Local initialization remains unavailable; delay loop stopped')
        if name=='pthread_once' and not int.from_bytes(self.read(a[0],4),'little'):
            self.uc.mem_write(a[0],b'\1\0\0\0');self.uc.reg_write(UC_ARM64_REG_PC,a[1]);return
        if name=='pthread_key_create':self.uc.mem_write(a[0],b'\1\0\0\0')
        elif name=='pthread_getspecific':v=self.thread_values.get(a[0],0)
        elif name=='pthread_setspecific':self.thread_values[a[0]]=a[1]
        elif name=='getpid':v=1000
        elif name=='getuid':v=10000
        elif name=='__errno':v=self.alloc(struct.pack('<I',2))
        elif name=='readlink':v=-1
        if name=='strlen':v=len(self.cstr(a[0]))
        elif name=='strcmp':v=int(self.cstr(a[0])!=self.cstr(a[1]))
        elif name=='memcmp':v=int(self.read(a[0],a[2])!=self.read(a[1],a[2]))
        elif name in ('malloc','calloc'):v=self.alloc(a[0]*(a[1] if name=='calloc' else 1))
        elif name=='__strncpy_chk':
            b=self.cstr(a[1]).encode();self.uc.mem_write(a[0],b[:a[2]]+bytes(max(0,a[2]-len(b))));v=a[0]
        self.finish(v)
    def jni(self,i):
        a=[self.reg(k) for k in range(8)]
        if i==6:
            s=self.cstr(a[1]);self.logs.append(['class',s])
            if not s.startswith(('java/','javax/','android/','dev/epro/','o/bwmna/','[')):return self.finish(0)
            return self.finish(self.obj(s))
        if i in (33,113,94,144):
            s=self.cstr(a[2]);sig=self.cstr(a[3]);self.logs.append(['member',self.objects.get(a[1]),s,sig]);return self.finish(self.obj([s,sig]))
        if i==145:return self.finish(self.obj([self.objects.get(a[1]),self.objects.get(a[2])]))
        if i==34 and self.objects.get(a[2],[''])[0]=='intern':return self.finish(a[1])
        if i==215:
            methods=[]
            for j in range(a[3]):
                p,q,fn=struct.unpack('<QQQ',self.read(a[2]+24*j,24));methods.append([self.cstr(p),self.cstr(q),hex(fn)])
            self.registrations.append([self.objects.get(a[1]),methods]);return self.finish()
        if i in (15,17,23,228,19,170,166,191,223):return self.finish()
        if i in (21,22,25):return self.finish(a[1])
        if i==163:return self.finish(self.obj(self.read(a[1],a[2]*2).decode('utf-16-le',errors='surrogatepass')))
        if i==167:return self.finish(self.obj(self.cstr(a[1])))
        raise ValueError(f'Unimplemented JNI index {i}; recent members={self.logs[-3:]}')

def main():
    p=argparse.ArgumentParser();p.add_argument('library',type=Path);p.add_argument('output',type=Path)
    a=p.parse_args();e=Probe(a.library)
    try:print('result',e.call(e.image.names['JNI_OnLoad'][0],e.vm,0,limit=5_000_000))
    except Exception as error:print(type(error).__name__,str(error),'pc',hex(e.uc.reg_read(UC_ARM64_REG_PC)))
    a.output.write_text(json.dumps({'logs':e.logs,'registrations':e.registrations},indent=2))
    print('registrations',e.registrations)

if __name__=='__main__':main()
