#!/usr/bin/env python3
"""Recover the two read-only JNI format constants and verify the real updater.

No native/Android code, accounts or authentication APIs are executed. The second
constant is a static catalog-format key, never transmitted as authorization.
"""
import argparse,base64,hashlib,json,subprocess,sys
from pathlib import Path
from urllib.request import Request,HTTPRedirectHandler,build_opener
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from scripts.apk_analysis.elf_inspect import ElfImage
HERE=Path(__file__).resolve().parent
SOURCE='https://raw.githubusercontent.com/Anurak2534/ohmvpn/refs/heads/main/newnamo.json'
LIB_SHA='c12426484f92371508ac44c9c207a03d1da4a2a97ec1e0ad5486effc95e17ebf'
def oracle(mode,key,values):
    lines=''.join(mode+'\t'+base64.b64encode(key).decode()+'\t'+base64.b64encode(v).decode()+'\n' for v in values)
    result=subprocess.run(['java',str(HERE/'CatalogOracle.java')],input=lines,text=True,capture_output=True,check=True,timeout=45)
    out=[base64.b64decode(x,validate=True) for x in result.stdout.splitlines()]
    if len(out)!=len(values):raise ValueError('Incomplete Java reference')
    return out
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ValueError('Updater redirect denied')
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);p.add_argument('--download',action='store_true');a=p.parse_args();d=a.private
    lib=d/'unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libapi-namo.so'
    assert hashlib.sha256(lib.read_bytes()).hexdigest()==LIB_SHA
    elf=ElfImage(lib);source=elf.cstring(0x4f0);key=elf.cstring(0x541).encode();assert source==SOURCE
    resolved=d/'resolved';original=d/'jadx1/sources'
    callback=(resolved/'defpackage/kd0.java').read_text()
    assert 'MainDetail.b()' in callback and 'j44.m(iz1.b(r3)' in callback
    assert '772515655' in (original/'defpackage/j44.java').read_text()
    assert 'okhttp/5.3.2' in (original/'defpackage/vd.java').read_text()
    report={'source':source,'nativeSha256':LIB_SHA,'jniGetters':{'a':'0x6b8/0x4f0','b':'0x6cc/0x541'},
      'formatKeyBytes':len(key),'formatKeySha256':hashlib.sha256(key).hexdigest(),'delta':772515655,
      'authorization':'none; format key is local decryption only','userAgent':'okhttp/5.3.2'}
    f=d/'native-constants.json';f.write_text(json.dumps({'a':source,'b':key.decode()}));f.chmod(0o600)
    if a.download:
        with build_opener(NoRedirect()).open(Request(source,headers={'User-Agent':'okhttp/5.3.2','Accept-Encoding':'identity'}),timeout=30) as r:
            data=r.read(8*1024*1024+1)
            assert r.status==200 and r.headers.get('Content-Encoding','identity')=='identity'
            assert data and len(data)<=8*1024*1024 and not data.lstrip().startswith(b'<')
            report['http']={'status':r.status,'contentType':r.headers.get('Content-Type'),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
        for name,value in [('remote.enc',data),('remote-oracle.json',oracle('D',key,[data])[0])]:
            f=d/name;f.write_bytes(value);f.chmod(0o600)
        doc=json.loads((d/'remote-oracle.json').read_text());assert isinstance(doc,dict)
        report['catalog']={'version':doc.get('Version'),'keys':list(doc),'counts':{k:len(v) for k,v in doc.items() if isinstance(v,list)}}
    (d/'recovery-report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
