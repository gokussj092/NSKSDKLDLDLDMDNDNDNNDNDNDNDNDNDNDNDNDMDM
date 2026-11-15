#!/usr/bin/env python3
"""Parse reviewed APK constants and fetch both fixed public catalogs; no APK code runs."""
import argparse,base64,hashlib,json,re
from pathlib import Path
from urllib.request import Request,HTTPRedirectHandler,build_opener
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
SOURCES={k:'https://raw.githubusercontent.com/apksdemons/apks2/refs/heads/main/speicers/spei_'+v for k,v in [('servers','servrs'),('users','users')]}
# App sets no User-Agent: this is an analytical runtime profile, not a physical
# or attested Android device. The public GET has no additional authentication.
HEADERS={'User-Agent':'Dalvik/2.1.0 (Linux; U; Android 14)','Accept-Encoding':'identity'}
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ValueError('Fixed source redirect denied')
def private(p,b):p.write_bytes(b);p.chmod(0o600)
def outer(data,password):
    raw=base64.b64decode(data,validate=True)
    if raw[:8]!=b'WakkoDev':raise ValueError('Wrong envelope')
    key=prior=b''
    while len(key)<48:prior=hashlib.md5(prior+password+raw[8:16]).digest();key+=prior
    return unpad(AES.new(key[:32],AES.MODE_CBC,key[32:48]).decrypt(raw[16:]),16)
def main():
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);p.add_argument('--download',action='store_true');a=p.parse_args();d=a.private
    assert hashlib.sha256((d/'unpacked/apks/netfree.mx.anuncios.apk').read_bytes()).hexdigest()=='13f9039e5c0df357d6bd8ea3e5a74cdf27201a505ad30106a204cfc759a85ccb'
    lookup={(x['path'],x['class']):x['value'] for x in json.loads((d/'arrays.json').read_text())}
    key=lookup['jadx2/sources/t5p215r1/z5geu5j6js.java','zhxk3yses']
    text=(d/'unpacked/extracted/netfree.mx.anuncios/assets/LICENSE').read_text();included=re.search(r'^NIGHT_MODE=(.*)$',text,re.M)[1]
    private(d/'recipe.json',json.dumps({'remotePassword':key,'includedPassword':included,'sources':SOURCES,'headers':HEADERS}).encode())
    report={'passwordSha256':hashlib.sha256(key.encode()).hexdigest(),'includedPasswordSha256':hashlib.sha256(included.encode()).hexdigest(),'samePassword':key==included,'userAgent':'ANALYTICAL_ANDROID_PROFILE_NO_APP_OVERRIDE','catalogs':[]}
    paths={k:d/'unpacked/extracted/netfree.mx.anuncios/assets/flags'/v for k,v in [('included-servers','config.png'),('included-users','usr.png')]}
    if a.download:
        for k,url in SOURCES.items():
            with build_opener(NoRedirect()).open(Request(url,headers=HEADERS),timeout=30) as r:
                data=r.read(8*1024*1024+1);assert r.status==200 and r.headers.get('Content-Encoding','identity')=='identity';assert data and len(data)<=8*1024*1024 and not data.lstrip().startswith(b'<')
                report[k+'Http']={'status':r.status,'contentType':r.headers.get('Content-Type'),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
            path=d/(k+'.enc');private(path,data);paths['remote-'+k]=path
    for k,path in paths.items():
        b=path.read_bytes();clear=outer(b,(included if k.startswith('included') else key).encode());doc=json.loads(clear);private(d/(k+'-outer.json'),clear)
        report['catalogs'].append({'name':k,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'keys':list(doc),'version':doc.get('Version'),'counts':{n:len(v) for n,v in doc.items() if isinstance(v,list)}})
    (d/'recovery-report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':main()
