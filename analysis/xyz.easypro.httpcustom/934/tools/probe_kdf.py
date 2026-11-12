"""Trace new local format KDF with public synthetic inputs, never real secrets."""
import argparse,json,struct,hashlib,base64
from pathlib import Path
from jni_format_probe import Probe
from unicorn.arm64_const import UC_ARM64_REG_PC
from unicorn import UC_HOOK_BLOCK
from collections import deque

def load(library,provider=False):
    e=Probe(library);base=Path(library).with_suffix('.format-state') if not provider else Path(str(Path(library).with_suffix(''))+'-provider.format-state')
    signature=hashlib.sha256(Path(library).read_bytes()).hexdigest()
    if base.with_suffix('.state.json').exists():
        s=json.loads(base.with_suffix('.state.json').read_text())
        assert s['library_sha256']==signature
        e.uc.mem_write(0,base.with_suffix('.memory.bin').read_bytes())
        e.uc.mem_write(e.HEAP,base.with_suffix('.heap.bin').read_bytes())
        for k in ('nextobj','next_alloc','logs','registrations'):setattr(e,k,s[k])
        e.objects={int(k):v for k,v in s['objects'].items()}
        return e
    if provider:e=load(library)
    else:e.call(e.image.names['JNI_OnLoad'][0],e.vm,0,limit=5_000_000)
    try:e.call(0xc9e088 if provider else 0xb189ac,e.env,0,1046 if provider else 2112,limit=50_000_000)
    except Exception as error:
        print(type(error).__name__,str(error),'pc',hex(e.uc.reg_read(UC_ARM64_REG_PC)),flush=True);raise
    end=max(seg['p_vaddr']+seg['p_memsz'] for seg in e.image.elf.iter_segments() if seg['p_type']=='PT_LOAD')
    base.with_suffix('.memory.bin').write_bytes(e.read(0,(end+4095)&~4095))
    base.with_suffix('.heap.bin').write_bytes(e.read(e.HEAP,e.next_alloc-e.HEAP))
    s={k:getattr(e,k) for k in ('nextobj','next_alloc','logs','registrations','objects')};s['library_sha256']=signature
    base.with_suffix('.state.json').write_text(json.dumps(s))
    return e

def main():
    p=argparse.ArgumentParser();p.add_argument('library');p.add_argument('output');p.add_argument('--entry',choices=['c','d','provider','envelope','native','context','init'],default='d');p.add_argument('--schedule',default='n15');p.add_argument('--session',action='store_true');p.add_argument('--family',type=int,default=1);a=p.parse_args()
    e=Probe(a.library) if a.entry in ('native','context') else load(a.library,provider=a.entry=='provider')
    original=e.jni
    def jni(i):
        args=[e.reg(k) for k in range(8)];obj=e.objects.get(args[1]);member=e.objects.get(args[2]);name=member[0] if isinstance(member,list) else None
        if i==150 and name=='SDK_INT':return e.finish(35)
        if i==32:return e.finish(1)
        if i in (95,96,100,101):
            value=obj.get(name,0) if isinstance(obj,dict) else 0
            if not value and i==95:value=e.obj({'__cls__':member[1][1:-1] if member else '?'})
            return e.finish(value)
        if i==31:return e.finish(e.obj(obj.get('__cls__','java/lang/Object') if isinstance(obj,dict) else '[B' if isinstance(obj,bytes) else 'java/lang/String'))
        if i==171:return e.finish(len(obj))
        if i in (168,164):return e.finish(len(obj))
        if i==169:return e.finish(e.alloc(obj.encode()+b'\0'))
        if i==176:return e.finish(e.obj(bytes(args[1])))
        if i==200:e.uc.mem_write(args[4],obj[args[2]:args[2]+args[3]]);return e.finish()
        if i==208:
            value=bytearray(obj);value[args[2]:args[2]+args[3]]=e.read(args[4],args[3]);e.objects[args[1]]=bytes(value);return e.finish()
        if i==173:return e.finish(obj[args[2]])
        if i==174:obj[args[2]]=args[3];return e.finish()
        if i==172:return e.finish(e.obj([args[3]]*args[1]))
        if i==24:return e.finish(int(args[1]==args[2]))
        if i==27:return e.finish(e.obj({'__cls__':obj,'buffer':[]}))
        if i in (34,36,114,116,141,143,37,39,49,51,52,54,117,119):
            values=struct.unpack('<8Q',e.read(args[3],64)) if i in (36,116,143,39,51,54,119) else tuple(args[3:]+[0]*3)
            if name=='getClass':return e.finish(e.obj('[B' if isinstance(obj,bytes) else 'java/lang/String'))
            if name=='currentThread':return e.finish(e.obj({'__cls__':'java/lang/Thread'}))
            if name=='getStackTrace':return e.finish(e.obj([]))
            if name=='myLooper':return e.finish(0)
            if name=='getService':return e.finish(0)
            if name=='intValue':return e.finish(obj)
            if name=='valueOf':return e.finish(e.obj(str(values[0] if member[1].startswith('(I)') else e.objects.get(values[0]))))
            if name=='toString':return e.finish(e.obj(str(obj)))
            if name=='getBytes':return e.finish(e.obj(obj.encode('utf-8')))
            if name=='toByteArray':return e.finish(e.obj(bytes(obj['buffer'])))
            if name=='add' and isinstance(obj,list):obj.append(values[0]);return e.finish(1)
            if name=='toArray' and isinstance(obj,list):return e.finish(e.obj(obj.copy()))
            if member[1]=='([Ljava/lang/Object;)Ljava/util/ArrayList;':return e.finish(e.obj(list(e.objects[values[0]])))
            if name=='J0' and member[1].startswith('(Ljava/lang/Iterable;Ljava/lang/String;'):
                return e.finish(e.obj(e.objects[values[1]].join(str(e.objects.get(x)) for x in e.objects[values[0]])))
            if name=='hashCode':
                h=0
                for char in obj:h=(h*31+ord(char))&0xffffffff
                return e.finish(h)
            if name=='equals':return e.finish(int(obj==e.objects.get(values[0])))
            if member[1]=='(Ljava/lang/String;)Z':return e.finish(int(e.objects.get(values[0]) in ('n12','n14','n16','n18')))
            if name=='e' and member[1]=='(Ljava/util/List;)Ljava/lang/String;':
                return e.finish(e.obj(','.join(e.objects.get(x) for x in e.objects[values[0]])))
            if name in ('N0','M0') and member[1]=='([B[B)[B':
                x,y=struct.unpack('<QQ',e.read(args[3],16));return e.finish(e.obj(e.objects[x]+e.objects[y]))
            if name=='intern':return e.finish(args[1])
            if member[1]=='(Ldev/epro/r0/V1470156706430288231;)V':return e.finish()
            if name=='a' and member[1].startswith('(I[B[B[B[B[BZ'):
                raise ValueError('FORMAT_KDF '+repr([e.objects.get(x,x) for x in values]))
            if name=='d' and member[1].startswith('(I[B[B[B[B[B[BZ'):
                values=struct.unpack('<9Q',e.read(args[3],72))
                raise ValueError('FORMAT_DERIVE '+repr([e.objects.get(x,x) for x in values]))
            if name=='q' and member[1]=='(IJJ[[B)[B':
                arrays=e.objects[values[3]]
                raise ValueError('NATIVE_FORMAT_OPERATION '+repr(list(values[:3])+[[e.objects.get(x,x) for x in arrays]]))
            if name=='c' and member[1].startswith('([BLjava/util/List;[BLjava/lang/Integer;'):
                values=struct.unpack('<9Q',e.read(args[3],72))
                raise ValueError('ENVELOPE_DERIVE '+repr([e.objects.get(x,x) for x in values]))
            raise ValueError('LOCAL_CALL '+repr(obj)+' '+repr(member)+' '+repr([e.objects.get(x,x) for x in args[3:]]))
        if i in (61,63,129,131,93):
            member=e.objects.get(args[2] if i!=93 else args[3]);name=member[0]
            values=struct.unpack('<8Q',e.read(args[4] if i==93 else args[3],64)) if i in (63,131,93) else tuple(args[3:]+[0]*3)
            if name in ('<init>','close'):return e.finish()
            if name=='write':
                if member[1]=='(I)V':obj['buffer'].append(values[0]&255)
                else:
                    value=e.objects[values[0]]
                    if member[1]=='([BII)V':value=value[values[1]:values[1]+values[2]]
                    obj['buffer'].extend(value)
                return e.finish()
            raise ValueError('LOCAL_VOIDCALL '+repr(obj)+' '+repr(member))
        return original(i)
    e.jni=jni
    if a.entry=='envelope':e.call(0xa0f614,e.env,0,899,limit=50_000_000)
    if a.entry=='init':e.call(0xc9e088,e.env,0,108,limit=50_000_000)
    params=e.obj({'__cls__':'dev/epro/r0/X8309369043615013050','a':e.obj('xyz.easypro.httpcustom'),'b':1,'c':934})
    self=e.obj({'__cls__':'dev/epro/r0/N6400668577528756650','b':params})
    arguments=[e.obj(x) for x in (bytes(range(32)),b'ssh,profiles',b'934',b'n15',b'',b'')]
    fn=(0x78694 if a.entry=='native' else 0x310f0) if a.entry in ('native','context') else int(next(x[2] for x in e.registrations[-1][1] if x[0]==('a' if a.entry in ('provider','envelope') else 'p' if a.entry=='init' else a.entry)),16)
    callargs=[5,*arguments,0] if a.entry=='d' else [e.obj(bytes(range(32))),e.obj([e.obj('ssh'),e.obj('profiles')]),0,e.obj(934),e.obj(a.schedule),0,0,0,int(a.session)]
    if a.entry=='provider':
        self=e.obj({'__cls__':'dev/epro/r0/Z16537246539122903131'})
        callargs=[a.family,*[e.obj(x) for x in (b'public-transcript',bytes(range(32)),b'public-info',b'',b'')],0,e.obj({'__cls__':'dev/epro/r0/S13398029567429928805'})]
    if a.entry=='envelope':
        self=e.obj({'__cls__':'dev/epro/r0/E11636605712876083652','a':e.obj({'__cls__':'dev/epro/r0/N6400668577528756650'})})
        envelope=e.obj({'__cls__':'dev/epro/r0/V6167873899234863698','a':e.obj([e.obj('ssh'),e.obj('profiles')]),'b':e.obj(bytes(range(32))),'e':e.obj(934),'f':0,'g':2,'h':67108864,'i':e.obj('n15'),'j':e.obj([]),'k':12,'l':0})
        callargs=[envelope,0,0,0]
    if a.entry=='init':self=0;callargs=[e.obj({'__cls__':'android/content/Context'})]
    if a.entry in ('native','context'):
        e.call(e.image.names['JNI_OnLoad'][0],e.vm,0,limit=5_000_000)
        self=0
        callargs=[1,0,a.family,e.obj([e.obj(x) for x in (b'public-transcript',bytes(range(32)),b'public-info',b'',b'')])]
        if a.entry=='context':callargs=[e.obj({'__cls__':'android/content/Context'})]
        trace=deque(maxlen=30)
        e.uc.hook_add(UC_HOOK_BLOCK,lambda u,p,s,d:trace.append(hex(p)))
    try:
        result=e.call(fn,e.env,self,*callargs,limit=10_000_000)
        print('result',result,repr(e.objects.get(result)))
    except Exception as error:
        print(str(error),'pc',hex(e.uc.reg_read(UC_ARM64_REG_PC)),'lr',hex(e.reg(30)))
        if a.entry in ('native','context'):print('blocks',list(trace))
    Path(a.output).write_text(json.dumps({'logs':e.logs,'registrations':e.registrations,'objects':{str(k):repr(v) for k,v in e.objects.items()}},indent=2))

if __name__=='__main__':main()
