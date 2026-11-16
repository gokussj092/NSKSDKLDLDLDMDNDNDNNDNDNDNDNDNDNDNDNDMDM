"""Fresh in-memory Android app directory for offline native format research.

Never reads/writes host paths, imports device state, or supplies activation
material. All buffers and handles exist only in the emulated process.
"""
import posixpath,struct

class MemoryFS:
    PREFIX='/data/user/0/xyz.easypro.httpcustom'
    def __init__(self,engine):
        self.e=engine;self.files={};self.dirs={self.PREFIX+'/'+x for x in ('no_backup','files','cache')}
        self.fds={};self.nextfd=10;self.errno=engine.alloc(struct.pack('<I',2))
    def fail(self,number=2):self.e.uc.mem_write(self.errno,struct.pack('<I',number));return -1
    def path(self,value,fd=None):
        path=self.e.cstr(value)
        if not path.startswith('/'):
            if fd not in self.fds:raise ValueError('Unknown relative directory')
            path=self.fds[fd]['path']+'/'+path
        path=posixpath.normpath(path)
        if not path.startswith(self.PREFIX+'/'):raise ValueError('Path outside virtual app directory')
        return path
    def opened(self,path,flags):
        directory=path in self.dirs
        if not directory and path not in self.files:
            if not flags&64:return self.fail()
            self.files[path]=bytearray()
        elif flags&64 and flags&128:return self.fail(17)
        if not directory and flags&512:self.files[path].clear()
        fd=self.nextfd;self.nextfd+=1;self.fds[fd]={'path':path,'position':0,'directory':directory};return fd
    def handle(self,name):
        e=self.e;a=[e.reg(i) for i in range(5)]
        if name=='__errno':return self.errno
        if name in ('open','open64','__open_2'):return self.opened(self.path(a[0]),a[1])
        if name in ('openat','__openat_2'):return self.opened(self.path(a[1],a[0]),a[2])
        if name=='close':self.fds.pop(a[0],None);return 0
        if name in ('fcntl','flock','fsync','fdatasync','fchmod'):return 0
        if name=='mkdir':self.dirs.add(self.path(a[0]));return 0
        if name in ('fstat','fstat64'):
            info=self.fds.get(a[0])
            if info is None:return self.fail(9)
            size=0 if info['directory'] else len(self.files[info['path']]);buf=bytearray(128)
            struct.pack_into('<Q',buf,8,a[0]);struct.pack_into('<IIII',buf,16,0o40700 if info['directory'] else 0o100600,1,10000,10000)
            struct.pack_into('<q',buf,48,size);struct.pack_into('<I',buf,56,4096);struct.pack_into('<q',buf,64,(size+511)//512)
            e.uc.mem_write(a[1],bytes(buf));return 0
        if name in ('read','write','pread64','pwrite64'):
            item=self.fds.get(a[0]);length=a[2]
            if item is None:return self.fail(9)
            if item['directory']:return self.fail(21)
            if length>1024*1024:raise ValueError('Virtual file buffer limit')
            content=self.files[item['path']];offset=a[3] if name.startswith('p') else item['position']
            if offset>1024*1024:raise ValueError('Virtual file offset limit')
            if name in ('read','pread64'):
                data=bytes(content[offset:offset+length]);e.uc.mem_write(a[1],data);count=len(data)
            else:
                data=e.read(a[1],length);end=offset+length
                if end>1024*1024:raise ValueError('Virtual file size limit')
                if end>len(content):content.extend(bytes(end-len(content)))
                content[offset:end]=data;count=length
            if not name.startswith('p'):item['position']=offset+count
            return count
        raise ValueError('Unmodelled virtual filesystem call '+name)

NAMES={'__errno','open','open64','__open_2','openat','__openat_2','close','fcntl','flock','fsync','fdatasync','fchmod','mkdir','fstat','fstat64','read','write','pread64','pwrite64'}
