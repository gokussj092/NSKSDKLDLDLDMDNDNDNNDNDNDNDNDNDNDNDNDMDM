#!/usr/bin/env python3
"""Recover reviewed Java format constants and test the included/original updater.

No APK, licensing, authentication guard or VPN account code is executed.
"""
import argparse,base64,hashlib,json,re,subprocess,time
from pathlib import Path
from urllib.request import Request,HTTPRedirectHandler,build_opener
HERE=Path(__file__).resolve().parent
SOURCE='https://raw.githubusercontent.com/soportecrisdev/Gen/main/Update'
USER_AGENT='HTTP-Conexion-VPN/3.0'
HEADERS={'User-Agent':USER_AGENT,'Accept':'*/*','Cache-Control':'no-cache, no-store, must-revalidate',
 'Pragma':'no-cache','Expires':'0','Accept-Encoding':'identity'}
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ValueError('Fixed updater redirect denied')
def oracle(mode,key,values):
    lines=''.join(mode+'\t'+base64.b64encode(key).decode()+'\t'+base64.b64encode(v).decode()+'\n' for v in values)
    done=subprocess.run(['java',str(HERE/'CatalogOracle.java')],input=lines,text=True,capture_output=True,check=True,timeout=45)
    out=[base64.b64decode(x,validate=True) for x in done.stdout.splitlines()]
    if len(out)!=len(values):raise ValueError('Incomplete JCA reference')
    return out
def private(path,data):
    path.write_bytes(data);path.chmod(0o600)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);p.add_argument('--download',action='store_true');p.add_argument('--remote-config',action='store_true');a=p.parse_args();d=a.private
    root=d/'unpacked';base=root/'apks/com.doriaxvpn.unlimited.apk'
    assert hashlib.sha256(base.read_bytes()).hexdigest()=='d55c4ce6181ccd82b1846fac4a2c2298b6e5f6e807b07509c84cfe654b777d82'
    cl=(d/'jadx1/sources/defpackage/cl.java').read_text()
    password=json.loads(re.search(r'b = ("(?:[^"\\]|\\.)*")',cl)[1])
    assert SOURCE in (d/'jadx1/sources/defpackage/bl.java').read_text()
    source=(d/'jadx3/sources/defpackage/pm1.java').read_text().split('public String toString()')[1]
    values=re.search(r'L11:\s*return new String\(new byte\[\]\{(.*?)\}\)',source,re.S)[1]
    items=[x.replace('(byte)','').strip() for x in values.split(',')]
    packet=(d/'jadx3/sources/com/trilead/ssh2/sftp/Packet.java').read_text()
    const=int(re.search(r'SSH_FXP_ATTRS = (\d+)',packet)[1])
    key=bytes((const if x=='Packet.SSH_FXP_ATTRS' else int(x))&255 for x in items)
    assert len(key)==16
    fetch=(d/'jadx1/sources/defpackage/uc1.java').read_text()
    assert USER_AGENT in fetch and 'nocache=' in fetch and 'no-cache, no-store, must-revalidate' in fetch
    chosen_source=SOURCE
    if a.remote_config:
        effective=json.loads((d/'firebase-effective.json').read_text())
        assert effective['source']=='https://raw.githubusercontent.com/soportecrisdev/Gen/main/new' and effective['password']==password
        chosen_source=effective['source']
    recipe={'source':chosen_source,'password':password,'field_key':key.decode()}
    private(d/'recipe.json',json.dumps(recipe,ensure_ascii=False).encode())
    report={'source':chosen_source,'remoteConfigSelected':a.remote_config,'passwordSha256':hashlib.sha256(password.encode()).hexdigest(),
      'fieldKeySha256':hashlib.sha256(key).hexdigest(),'fieldKeyBytes':len(key),'userAgent':USER_AGENT,'catalogs':[]}
    paths=[root/'extracted/com.doriaxvpn.unlimited/assets/config.json']
    if a.download:
        url=chosen_source+'?nocache='+str(int(time.time()*1000))
        with build_opener(NoRedirect()).open(Request(url,headers=HEADERS),timeout=30) as r:
            data=r.read(8*1024*1024+1);assert r.status==200 and r.headers.get('Content-Encoding','identity')=='identity'
            assert data and len(data)<=8*1024*1024 and not data.lstrip().startswith(b'<')
            report['http']={'status':r.status,'bytes':len(data),'contentType':r.headers.get('Content-Type'),'sha256':hashlib.sha256(data).hexdigest(),'cachebuster':True}
        private(d/'remote.enc',data);paths.append(d/'remote.enc')
    for path in paths:
        data=path.read_bytes();clear=oracle('O',password.encode(),[data])[0];doc=json.loads(clear);assert isinstance(doc,dict)
        private(d/(path.stem+'-outer.json'),clear)
        report['catalogs'].append({'source':path.name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
          'version':doc.get('Version'),'keys':list(doc),'counts':{k:len(v) for k,v in doc.items() if isinstance(v,list)}})
    (d/'recovery-report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
