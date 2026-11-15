"""Version-only auto recovery with private, atomic JSON history; no catalogs."""
from __future__ import annotations
import contextlib,json,os,stat,time,warnings
from datetime import datetime,timezone
from pathlib import Path
from uuid import uuid4

SEED_PATH=Path(__file__).with_name('builds.seed.json')
MAX_STATE=1024*1024;MAX_BUILD=2147483647
def seed():return json.loads(SEED_PATH.read_text())
def state_path():
    configured=os.environ.get('CLOUD_TUNNELTWEAK_BUILD_STATE_PATH')
    return Path(configured) if configured else Path(os.environ.get('XDG_STATE_HOME',str(Path.home()/'.local/state')))/'spdecode/tunneltweak-builds.json'
def valid_build(n):return type(n) is int and 0<n<=MAX_BUILD
def validate(s):
    if (not isinstance(s,dict) or set(s)!={'schemaVersion','provider','auto','builds'} or
        type(s['schemaVersion']) is not int or s['schemaVersion']!=1 or s['provider']!='tunneltweak' or not isinstance(s['auto'],dict) or
        set(s['auto'])!={'enabled','build'} or s['auto']['enabled'] is not True or
        not valid_build(s['auto']['build']) or not isinstance(s['builds'],list) or len(s['builds'])>4096):raise ValueError('BUILD_STATE_INVALID')
    seen=set()
    for r in s['builds']:
        if (not isinstance(r,dict) or set(r)!={'build','working','checks','successes','lastCheckedAt','lastHttpStatus','lastCode'} or
            not valid_build(r['build']) or r['build'] in seen or r['working'] is not None and type(r['working']) is not bool or
            type(r['checks']) is not int or type(r['successes']) is not int or not 0<=r['successes']<=r['checks'] or
            r['lastHttpStatus'] is not None and (type(r['lastHttpStatus']) is not int or not 100<=r['lastHttpStatus']<=599) or
            r['lastCheckedAt'] is not None and (not isinstance(r['lastCheckedAt'],str) or len(r['lastCheckedAt'])>32) or
            r['lastCode'] not in {'NOT_TRIED','DOWNLOAD_OK','UPDATE_REQUIRED','TEMPORARY_FAILURE','RESPONSE_INVALID'}):raise ValueError('BUILD_STATE_INVALID')
        seen.add(r['build'])
    if s['auto']['build'] not in seen:raise ValueError('BUILD_STATE_INVALID')
    return s
def load(path):
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as f:
            info=os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size>MAX_STATE:raise ValueError('BUILD_STATE_INVALID')
            return validate(json.loads(f.read(MAX_STATE+1)))
    except FileNotFoundError:return seed()
    except (OSError,ValueError,TypeError,RecursionError):
        warnings.warn('Tunneltweak BUILD_STATE_UNAVAILABLE',RuntimeWarning);return seed()
def empty(build):return dict(build=build,working=None,checks=0,successes=0,lastCheckedAt=None,lastHttpStatus=None,lastCode='NOT_TRIED')
def record(path,build,status,code,next_build=None):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700);lock=Path(str(path)+'.lock');fd=None
    for _ in range(100):
        try:fd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);break
        except FileExistsError:
            with contextlib.suppress(FileNotFoundError):
                if time.time()-lock.stat().st_mtime>60:lock.unlink()
            time.sleep(.02)
    if fd is None:raise OSError('BUILD_STATE_BUSY')
    tmp=Path(str(path)+'.'+str(uuid4())+'.tmp')
    try:
        s=load(path);row=next((r for r in s['builds'] if r['build']==build),None)
        if row is None:row=empty(build);s['builds'].append(row)
        row['checks']+=1;row['lastCheckedAt']=datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z')
        row['lastHttpStatus']=status;row['lastCode']=code
        if code=='DOWNLOAD_OK':row['working']=True;row['successes']+=1;s['auto']['build']=max(s['auto']['build'],build)
        if code=='UPDATE_REQUIRED':row['working']=False
        if next_build:
            if not any(r['build']==next_build for r in s['builds']):s['builds'].append(empty(next_build))
            s['auto']['build']=max(s['auto']['build'],next_build)
        s['builds'].sort(key=lambda r:r['build']);validate(s)
        encoded=json.dumps(s,indent=2)+'\n'
        if len(encoded.encode())>MAX_STATE:raise ValueError('BUILD_STATE_LIMIT')
        out=os.open(tmp,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(out,'w') as f:f.write(encoded);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        with contextlib.suppress(FileNotFoundError):tmp.unlink()
        os.close(fd)
        with contextlib.suppress(FileNotFoundError):lock.unlink()
def safe_record(*args):
    try:record(*args)
    except (OSError,ValueError,TypeError):warnings.warn('Tunneltweak BUILD_STATE_SAVE_FAILED',RuntimeWarning)
def _constant(_):raise ValueError('INVALID_JSON')
def _parse(data):return json.loads(data.decode('utf-8-sig'),parse_constant=_constant)
def update_required(data):
    try:
        if len(data)>65536:return False
        d=_parse(data);return isinstance(d,dict) and d.get('status')=='update_required'
    except (ValueError,UnicodeError,TypeError,RecursionError):return False
def next_build(data,current):
    try:
        if len(data)>65536:return None
        d=_parse(data)
        if not isinstance(d,dict) or d.get('status')!='update_required':return None
        if 'minVersionCode' in d:
            n=d['minVersionCode'];return n if valid_build(n) and n>current else None
        return current+1 if current<MAX_BUILD else None
    except (ValueError,UnicodeError,TypeError,RecursionError):return None
def valid_download(data):
    try:
        import re
        if not 0<len(data)<=8*1024*1024:return False
        d=_parse(data)
        if not isinstance(d,dict) or d.get('success') is False or d.get('status') in {'error','update_required'}:return False
        if isinstance(d.get('data'),str):
            b=re.sub(r'\s','',d['data']);return len(b)>=60 and len(b)%4==0 and re.fullmatch(r'[A-Za-z0-9+/]+={0,2}',b) is not None
        return isinstance(d.get('servers'),list) and bool(d['servers']) and isinstance(d.get('configs'),list)
    except (ValueError,UnicodeError,TypeError,RecursionError):return False
