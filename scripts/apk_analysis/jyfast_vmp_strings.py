#!/usr/bin/env python3
"""Recover pinned JyFast 9 VMP string constants offline, with a modeled JNI context.

No network or real OS execution. Background thread creation is recorded but its
code is not executed. This verifies constant recovery, not an Android startup.
Inputs are the original ARM64 libprominexVMP+.so and base APK; neither ships in Git.
"""
from pathlib import Path
import struct,sys,time,base64,hashlib,zipfile,argparse,json,contextlib,io
sys.path.insert(0,str(Path(__file__).resolve().parent))
from arm64_function import Arm64Function
from unicorn import UC_HOOK_MEM_INVALID,UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_PC,UC_ARM64_REG_X0,UC_ARM64_REG_X30

class Probe(Arm64Function):
 def __init__(self,p,apk):
  if hashlib.sha256(Path(p).read_bytes()).hexdigest() != 'fcf34bb13c2b6ca3e76a804ed90bc3dc1e142ed28cd9d9ad29d2a78389da988a':
   raise ValueError('Unsupported native build')
  self.apk_path=Path(apk)
  with zipfile.ZipFile(apk) as archive:self.asset_content=archive.read('assets/prominex-vmp+.vmp')
  if hashlib.sha256(self.asset_content).hexdigest() != '3b1497a20a8adad9d8fc86057a27b3689f28290ed4e45675fec97ed29cbb84be':
   raise ValueError('Unsupported VMP asset')
  super().__init__(p)
  self.sizes={};self.stubs={};self.strings=[];self.methods={};self.assets={};self.fields={};self.thread_values={};self.next_thread_key=1
  self.table=self.alloc(0x1000);self.env=self.alloc(struct.pack('<Q',self.table))
  syms=self.image.elf.get_section_by_name('.dynsym');imports={}
  for rel in self.image.relocations:
   if rel['r_info_type'] in [257,1025,1026]:
    sym=syms.get_symbol(rel['r_info_sym']);name=sym.name
    if name not in imports:
     addr=self.STOP+0x800+len(imports)*4;imports[name]=addr;self.image.plt[addr]=name
    value=(imports[name]+rel['r_addend'])%2**64
    self.uc.mem_write(rel['r_offset'],struct.pack('<Q',value))
  for i in range(256):
   a=self.STOP+0x100+i*4;self.stubs[a]=i
   self.uc.mem_write(self.table+i*8,struct.pack('<Q',a))
  self.uc.hook_del(self.step_hook)
  sec=self.image.elf.get_section_by_name('.plt')
  self.uc.hook_add(UC_HOOK_CODE,self._step,begin=sec['sh_addr'],end=sec['sh_addr']+sec['sh_size'])
  self.uc.hook_add(UC_HOOK_CODE,self._step,begin=self.STOP+0x100,end=self.STOP+0xfff)
  self.uc.hook_add(UC_HOOK_MEM_INVALID,lambda uc,access,addr,size,value,u:print('INVALID MEMORY',hex(addr),'pc',hex(uc.reg_read(UC_ARM64_REG_PC))))
 def cstring(self,a):
  b=bytearray()
  for i in range(1000000):
   c=self.read(a+i,1)
   if c==b'\0':return bytes(b)
   b.extend(c)
  raise ValueError('string bound')
 def _step(self,uc,a,size,u):
  name=self.image.plt.get(a)
  idx=self.stubs.get(a)
  try:
   r=0
   if idx is not None:
    if idx==6:
     print('FindClass',self.cstring(self.reg(1)));r=self.reg(1)
    elif idx in [94,144]:
     field=self.cstring(self.reg(2));print('FieldID',field);r=self.alloc(8);self.fields[r]=field
    elif idx in [95,145]:
     field=self.fields[self.reg(2)];print('ObjectField',field)
     if field in [b'mInitialApplication',b'mBoundApplication',b'info',b'mApplicationInfo',b'appInfo']:r=self.alloc(b'modeled-object\0')
     elif field in [b'sourceDir',b'mAppDir']:r=self.alloc(str(self.apk_path).encode()+b'\0')
     elif field==b'AESJEN':r=self.alloc(b'Key: =Kenova_code\0')
     else:raise ValueError('unsupported field '+repr(field))
    elif idx in [33,113]:
     name,sig=self.cstring(self.reg(2)),self.cstring(self.reg(3));print('MethodID',name,sig);r=self.alloc(8);self.methods[r]=(name,sig)
    elif idx in [34,35,36,114,115,116]:
     name,sig=self.methods[self.reg(2)];print('CallObject',name)
     if name in [b'currentApplication',b'currentActivityThread',b'createAppContext',b'getApplication',b'getApplicationContext',b'getAssets']:r=self.alloc(b'modeled-object\0')
     elif name==b'getPackageName':r=self.alloc(b'http.jyfast.vpnultra\0')
     elif name==b'trim':r=self.alloc(self.cstring(self.reg(1)).strip()+b'\0')
     elif name==b'b' and self.cstring(self.reg(1))==b'Rt':
      args=struct.unpack('<QQ',self.read(self.reg(3),16));key=self.cstring(args[0]);source=self.cstring(args[1]).decode()
      from Crypto.Cipher import AES
      from Crypto.Util.Padding import unpad
      abc='!?-=∆×÷ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';std='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
      ct=base64.b64decode(''.join(std[abc.index(c)] for c in source),validate=True)
      out=unpad(AES.new(hashlib.sha256(key).digest(),AES.MODE_CBC,bytes(16)).decrypt(ct),16)
      print('Rt.b actual key',key,'cipher bytes',len(ct),'result bytes',len(out));r=self.alloc(out+b'\0')
     else:raise ValueError('unsupported method '+repr(name))
    elif idx in [37,38,39]:
     name,sig=self.methods[self.reg(2)];print('CallBoolean',name)
     if name==b'isEmpty':r=int(not self.cstring(self.reg(1)))
     elif name==b'startsWith':
      arg=struct.unpack('<Q',self.read(self.reg(3),8))[0];r=int(self.cstring(self.reg(1)).startswith(self.cstring(arg)))
     else:raise ValueError('unsupported boolean '+repr(name))
    elif idx in [49,50,51]:
     name,sig=self.methods[self.reg(2)];print('CallInt',name)
     if name==b'length':r=len(self.cstring(self.reg(1)).decode().encode('utf-16-le'))//2
     else:raise ValueError('unsupported int '+repr(name))
    elif idx==31:r=self.alloc(b'modeled-class\0')
    elif idx==32:r=1
    elif idx==163:
     b=self.read(self.reg(1),self.reg(2)*2).decode('utf-16-le').encode();self.strings.append(b);r=self.alloc(b+b'\0')
    elif idx==167:
     b=self.cstring(self.reg(1));self.strings.append(b);r=self.alloc(b+b'\0')
    elif idx==169:r=self.reg(1)
    elif idx==168:r=len(self.cstring(self.reg(1)))
    elif idx==164:r=len(self.cstring(self.reg(1)).decode('utf-8').encode('utf-16-le'))//2
    elif idx==165:r=self.alloc(self.cstring(self.reg(1)).decode('utf-8').encode('utf-16-le'))
    elif idx==171:r=len(self.arrays[self.reg(1)])
    elif idx==173:r=self.arrays[self.reg(1)][self.reg(2)]
    elif idx in [20,21,25]:r=self.reg(1)
    elif idx in [19,22,23,166,170]:r=0
    elif idx==228:r=0
    else:raise ValueError('JNI '+str(idx)+' args '+str([hex(self.reg(i)) for i in range(4)]))
   elif name in ['malloc','calloc','realloc']:
    n=self.reg(0) if name=='malloc' else self.reg(0)*self.reg(1) if name=='calloc' else self.reg(1)
    if n>8000000:raise ValueError('alloc bound')
    r=self.alloc(n);self.sizes[r]=n
    if name=='realloc' and self.reg(0):uc.mem_write(r,self.read(self.reg(0),min(n,self.sizes.get(self.reg(0),0))))
   elif name=='posix_memalign':
    n=self.reg(2);ptr=self.alloc(n);self.sizes[ptr]=n;uc.mem_write(self.reg(0),struct.pack('<Q',ptr))
   elif name=='free':r=0
   elif name=='getauxval':r=0
   elif name=='sysconf':r=4096
   elif name=='__errno':r=self.alloc(4)
   elif name=='clock_gettime':
    n=time.time_ns() if self.reg(0)==0 else time.monotonic_ns();uc.mem_write(self.reg(1),struct.pack('<qq',n//1000000000,n%1000000000))
   elif name=='getenv':print('getenv',self.cstring(self.reg(0)));r=0
   elif name=='pthread_key_create':
    uc.mem_write(self.reg(0),struct.pack('<I',self.next_thread_key));self.next_thread_key+=1
   elif name=='pthread_setspecific':self.thread_values[self.reg(0)]=self.reg(1)
   elif name=='pthread_getspecific':r=self.thread_values.get(self.reg(0),0)
   elif name in ['pthread_attr_init','pthread_attr_setstacksize','pthread_attr_destroy','pthread_detach']:r=0
   elif name=='pthread_create':
    print('Background thread modeled, not executed',hex(self.reg(2)));uc.mem_write(self.reg(0),struct.pack('<Q',1))
   elif name=='getrandom':
    n=self.reg(1)
    if n>4096:raise ValueError('random bound')
    uc.mem_write(self.reg(0),bytes((i*17+29)%256 for i in range(n)));r=n
   elif name=='AAssetManager_fromJava':r=0x1234
   elif name=='AAssetManager_open':
    key=self.cstring(self.reg(1)).decode();print('AssetOpen',key)
    if key!='prominex-vmp+.vmp':raise ValueError('unknown asset')
    r=self.alloc(8);self.assets[r]=[self.asset_content,0]
   elif name=='AAsset_getLength':r=len(self.assets[self.reg(0)][0])
   elif name=='AAsset_read':
    data,pos=self.assets[self.reg(0)];chunk=data[pos:pos+self.reg(2)];uc.mem_write(self.reg(1),chunk);self.assets[self.reg(0)][1]+=len(chunk);r=len(chunk)
   elif name=='AAsset_close':r=0
   elif name=='strlen':r=len(self.cstring(self.reg(0)))
   elif name=='memcmp':
    b,c=self.read(self.reg(0),self.reg(2)),self.read(self.reg(1),self.reg(2));r=0 if b==c else 1 if b>c else -1
   elif name=='memmove':
    uc.mem_write(self.reg(0),self.read(self.reg(1),self.reg(2)));r=self.reg(0)
   else:return super()._step(uc,a,size,u)
   uc.reg_write(UC_ARM64_REG_X0,r&((1<<64)-1));uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_X30))
  except Exception as e:self.error=e;uc.emu_stop()


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('library',type=Path);parser.add_argument('apk',type=Path)
 parser.add_argument('--ids',default='2274,2372,2373,2374,2376,2402,2404,2405,2442,2443,2444,2445,2446,2447,2448,2449')
 args=parser.parse_args();ids=[int(x) for x in args.ids.split(',')]
 if not ids or len(ids)>10000 or any(x<0 or x>=8359 for x in ids):parser.error('String IDs out of range')
 with contextlib.redirect_stdout(io.StringIO()):
  p=Probe(args.library,args.apk)
  p.call(0x5c110,p.env,0,p.alloc(b'http.jyfast.vpnultra\0'),limit=300000000)
  strings={}
  for index in ids:
   p.strings=[];p.call(0x5b06c,p.env,0,index,limit=2000000)
   if len(p.strings)!=1:raise ValueError('Unexpected native string result')
   strings[str(index)]=p.strings[0].decode('utf-8')
 print(json.dumps({'build':9,'nativeStringsRecovered':len(strings),'backgroundThreadsExecuted':False,'strings':strings},ensure_ascii=False))

if __name__=='__main__':main()
