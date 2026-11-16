"""Trace original native format operation with public synthetic input only."""
import argparse,json,sys,struct,os
from pathlib import Path
from collections import Counter,deque
from jni_format_probe import Probe
from native_memory_fs import MemoryFS,NAMES as FS_NAMES
from unicorn import UC_HOOK_BLOCK,UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_PC,UC_ARM64_REG_X30,UC_ARM64_REG_X29

def main():
    p=argparse.ArgumentParser();p.add_argument('library');p.add_argument('--family',type=int,default=1)
    p.add_argument('--skip-local-abort',action='store_true',help='Offline emulation only; no activation or OS state is changed')
    p.add_argument('--model-local-risk-clean',action='store_true',help='Model the local callback synthetically; its full semantics are not established and no attestation/grant is issued')
    p.add_argument('--risk-model-value',type=int,choices=(0,1),default=0)
    p.add_argument('--operation',type=int,choices=(1,2),default=1)
    p.add_argument('--family5-inputs',action='store_true')
    p.add_argument('--public-certificate',type=Path,help='Model public APK package/signature context; never a device key or grant')
    p.add_argument('--diagnostics',action='store_true',help='Include bounded control-flow/import/filesystem metadata, never input buffers or keys')
    a=p.parse_args()
    e=Probe(a.library);e.call(e.image.names['JNI_OnLoad'][0],e.vm,0,limit=5000000)
    imported=e.imported;fs=MemoryFS(e);import_counts=Counter();fs_events=[]
    def native_import(name):
        if a.diagnostics:import_counts[name]+=1
        if name in FS_NAMES:
            event={'call':name}
            if a.diagnostics and name in ('openat','__openat_2'):
                path=e.cstr(e.reg(1))
                event.update(relative_path=not path.startswith('/'),basename_chars=len(path.rsplit('/',1)[-1]),flags=e.reg(2),caller=hex(e.reg(30)))
            result=fs.handle(name)
            if a.diagnostics:
                event.update(result='errno-pointer' if name=='__errno' else result,file_count=len(fs.files))
                if len(fs_events)<128:fs_events.append(event)
            return e.finish(result)
        if name=='sysconf':
            value=e.reg(0)
            if value in (0x27,30):return e.finish(4096)
            raise ValueError('Unmodelled sysconf '+str(value))
        if name in ('mmap','mmap64'):
            length=e.reg(1)
            if not 0<length<=1024*1024:raise ValueError('mmap model limit')
            e.next_alloc=(e.next_alloc+4095)&~4095
            return e.finish(e.alloc(length))
        if name in ('mprotect','mlock','munlock','munmap','madvise'):
            pointer,length=e.reg(0),e.reg(1)
            if not e.HEAP<=pointer<e.HEAP+0x1000000 or not 0<=length<=1024*1024:
                raise ValueError('Out-of-model memory operation '+name)
            return e.finish(0)
        if name=='syscall':
            number=e.reg(0)
            if number==278:
                pointer,length=e.reg(1),e.reg(2)
                if not 0<=length<=4096:raise ValueError('getrandom request exceeds model limit')
                e.uc.mem_write(pointer,os.urandom(length));return e.finish(length)
            raise ValueError('Unmodelled syscall '+str(number)+' args '+repr([e.reg(i) for i in (1,2,3)]))
        return imported(name)
    e.imported=native_import
    for address,name in list(e.image.plt.items()):
        if name in FS_NAMES or name in ('syscall','sysconf','mmap','mmap64','mprotect','mlock','munlock','munmap','madvise'):
            del e.image.plt[address];e.observers[address]=lambda instance,n=name:instance.imported(n)
    for address,observer in list(e.observers.items()):
        defaults=getattr(observer,'__defaults__',None)
        if defaults and isinstance(defaults[-1],str) and defaults[-1] in FS_NAMES:
            name=defaults[-1];e.observers[address]=lambda instance,n=name:instance.imported(n)
    signature=e.obj({'__cls__':'android/content/pm/Signature','der':a.public_certificate.read_bytes()}) if a.public_certificate else 0
    signatures=e.obj([signature]) if signature else 0
    signing=e.obj({'__cls__':'android/content/pm/SigningInfo'})
    package=e.obj({'__cls__':'android/content/pm/PackageInfo','versionCode':934,'signatures':signatures,'signingInfo':signing})
    manager=e.obj({'__cls__':'android/content/pm/PackageManager'})
    binder=e.obj({'__cls__':'android/os/IBinder','descriptor':'android.content.pm.IPackageManager'})
    context=e.obj({'__cls__':'android/app/Application'})
    original=e.jni
    def jni(index):
        args=[e.reg(i) for i in range(8)]
        obj=e.objects.get(args[1]);member=e.objects.get(args[2])
        name=member[0] if isinstance(member,list) else None
        if index in (34,36,114,116):
            values=struct.unpack('<8Q',e.read(args[3],64)) if index in (36,116) else tuple(args[3:]+[0]*3)
            if name=='currentThread':return e.finish(e.obj({'__cls__':'java/lang/Thread'}))
            if name=='getStackTrace':return e.finish(e.obj([]))
            if name=='myLooper':return e.finish(0)
            if name=='getClass':return e.finish(e.obj('[B' if isinstance(obj,bytes) else 'java/lang/Object'))
            if a.public_certificate:
                if name=='getService':
                    service=e.objects.get(values[0],values[0])
                    if service=='package':return e.finish(binder)
                    raise ValueError('Unmodelled Android Binder service: '+str(service))
                if name=='getInterfaceDescriptor':return e.finish(e.obj('android.content.pm.IPackageManager'))
                if name=='obtain' and obj=='android/os/Parcel':return e.finish(e.obj({'__cls__':'android/os/Parcel','written':[]}))
                if name=='createFromParcel':return e.finish(package)
                if name=='readStrongBinder':return e.finish(binder)
                if name in ('getApplicationContext','currentApplication','getInitialApplication'):return e.finish(context)
                if name=='getPackageName':return e.finish(e.obj('xyz.easypro.httpcustom'))
                if name=='getPackageManager':return e.finish(manager)
                if name in ('getNoBackupFilesDir','getFilesDir','getCacheDir'):
                    leaf={'getNoBackupFilesDir':'no_backup','getFilesDir':'files','getCacheDir':'cache'}[name]
                    return e.finish(e.obj({'__cls__':'java/io/File','path':'/data/user/0/xyz.easypro.httpcustom/'+leaf}))
                if name=='getAbsolutePath' and isinstance(obj,dict) and 'path' in obj:return e.finish(e.obj(obj['path']))
                if name=='getPackageInfo':return e.finish(package)
                if name in ('getSigningCertificateHistory','getApkContentsSigners'):return e.finish(signatures)
                if name=='toByteArray' and isinstance(obj,dict) and 'der' in obj:return e.finish(e.obj(obj['der']))
        if index in (37,39,117,119) and name=='hasMultipleSigners':return e.finish(0)
        if a.public_certificate and index in (37,39) and name=='transact':return e.finish(1)
        if a.public_certificate and index in (49,51) and name=='readInt':return e.finish(1)
        if a.public_certificate and index in (52,54) and name=='getLongVersionCode':return e.finish(934)
        if a.public_certificate and index in (61,63) and name in ('writeInterfaceToken','writeString','writeInt','writeLong','readException','recycle','setDataPosition'):
            return e.finish()
        if index in (95,100) and isinstance(obj,dict) and name in obj:return e.finish(obj[name])
        if index==150 and name=='SDK_INT':return e.finish(35)
        if index==171:return e.finish(len(obj))
        if index in (164,168):return e.finish(len(obj))
        if index==169:
            if not isinstance(obj,str):raise ValueError('Expected modelled Java string')
            return e.finish(e.alloc(obj.encode()+b'\0'))
        if index==173:return e.finish(obj[args[2]])
        if index==172:return e.finish(e.obj([args[3]]*args[1]))
        if index==174:obj[args[2]]=args[3];return e.finish()
        if index==176:return e.finish(e.obj(bytes(args[1])))
        if index==200:e.uc.mem_write(args[4],obj[args[2]:args[2]+args[3]]);return e.finish()
        if index==208:
            value=bytearray(obj);value[args[2]:args[2]+args[3]]=e.read(args[4],args[3]);e.objects[args[1]]=bytes(value);return e.finish()
        return original(index)
    e.jni=jni
    if a.skip_local_abort:
        e.observers[0x1d0f90]=lambda instance:instance.finish(0)
        e.uc.hook_add(UC_HOOK_CODE,e._step,begin=0x1d0f90,end=0x1d0f90)
    if a.model_local_risk_clean:
        # The original q thunk supplies 0x76d24 as its local callback. Its full
        # semantics are not established. This substitution is only diagnostic.
        e.observers[0x76d24]=lambda instance:instance.finish(a.risk_model_value)
        e.uc.hook_add(UC_HOOK_CODE,e._step,begin=0x76d24,end=0x76d24)
    ranges=[(s['p_vaddr'],s['p_vaddr']+s['p_memsz']) for s in e.image.elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_flags']&1]
    history=deque(maxlen=64);abort_frames=[];phase_diagnostics={}
    def block(u,address,size,data):
        history.append((hex(address),hex(u.reg_read(UC_ARM64_REG_X30))))
        if address==0x1d0f90:
            fp=u.reg_read(UC_ARM64_REG_X29)
            for _ in range(15):
                if not e.STACK<=fp<e.STACK+0x100000:break
                prev,lr=struct.unpack('<QQ',e.read(fp,16));abort_frames.append((hex(fp),hex(lr)))
                if prev<=fp:break
                fp=prev
        if address<0x26000:
            e.error=ValueError('Control left executable code');u.emu_stop()
    e.uc.hook_add(UC_HOOK_BLOCK,block)
    inputs=(('H'+'0'*31).encode(),bytes(range(32)),b'',bytes(range(32)),b'') if a.family5_inputs else (b'public-transcript',bytes(range(32)),b'public-info',b'',b'')
    arrays=e.obj([e.obj(x) for x in inputs])
    def save_phase(name):
        if a.diagnostics:
            phase_diagnostics[name]={'last_blocks':list(history),'import_counts':dict(import_counts),'filesystem_events':list(fs_events)}
        history.clear();import_counts.clear();fs_events.clear()
    try:
        if a.public_certificate:
            history.clear()
            init=e.call(0x310f0,e.env,0,context,limit=2000000)
            save_phase('public_context_initialization')
            print(json.dumps({'public_context_initialization_result':init,'genuine_device_attestation':False}),file=sys.stderr)
        result=e.call(0x78694,e.env,0,a.operation,0,a.family,arrays,limit=2000000)
        value=e.objects.get(result)
        output={'returned_type':type(value).__name__,'returned_null':result==0,
                'byte_length':len(value) if isinstance(value,bytes) else None}
        save_phase('format_operation')
        if a.diagnostics:output['diagnostics']=phase_diagnostics
        print(json.dumps(output))
    except Exception as error:
        print(json.dumps({'error':str(error),'pc':hex(e.uc.reg_read(UC_ARM64_REG_PC)),
                         'lr':hex(e.uc.reg_read(UC_ARM64_REG_X30)),'blocks':list(history),
                         'abort_frames':abort_frames,
                         'recent_jni_members':e.logs[-8:]},indent=2))
if __name__=='__main__':main()
