#!/usr/bin/env python3
"""Census every field and compare complete APK/remote documents against JCA."""
import argparse,base64,hashlib,json,re,subprocess,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.HTTP_FenixVPN import codec as shared
from recover import outer,private
HERE=Path(__file__).resolve().parent
def oracle(mode,key,values):
    wire=''.join(mode+'\t'+base64.b64encode(key).decode()+'\t'+base64.b64encode(v).decode()+'\n' for v in values)
    p=subprocess.run(['java',str(HERE/'CatalogOracle.java')],input=wire,text=True,capture_output=True,check=True,timeout=60)
    result=[base64.b64decode(x,validate=True) for x in p.stdout.splitlines()];assert len(result)==len(values);return result
def main():
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();d=a.private
    recipe=json.loads((d/'recipe.json').read_text());resources=json.loads((d/'resource-fields.json').read_text());key=recipe['fieldPassword'].encode()[:32].ljust(32,b'\0');reports=[]
    for name,section in [('included-servers','Servers'),('included-users','Usuarios'),('remote-servers','Servers'),('remote-users','Usuarios')]:
        path=d/'unpacked/extracted/netfree.mx.anuncios/assets/flags'/('config.png' if section=='Servers' else 'usr.png') if name.startswith('included') else d/('servers.enc' if section=='Servers' else 'users.enc')
        data=path.read_bytes();password=recipe['includedPassword' if name.startswith('included') else 'remotePassword'].encode();clear=oracle('O',password,[data])[0];assert clear==outer(data,password)
        obj=json.loads(clear);fields=shared.SERVER_FIELDS if section=='Servers' else shared.USER_FIELDS;names=Counter(k for row in obj[section] for k in row)
        unknown=[k for k in names if re.fullmatch(r'[A-Za-z0-9+/]{22}==',k) and k not in fields and any(isinstance(row.get(k),str) for row in obj[section])];assert not unknown
        if section=='Servers':
            identity={'p0PgL3l0d89mnssz7ImPJA==','ACqWMY4zuZWzSEs8cZMXIw==','66P9ZUEM1ju4WGhv856BSg=='}
            helper=(d/'decoded/jadx2/sources/netfree/mx/anuncios/servers/zhxk3yses.java').read_text();assert all(json.dumps(k) in helper for k in identity);assert fields-identity<=set(resources.values()),'Opaque field names differ from APK resources'
        values=list(dict.fromkeys(row[k] for row in obj[section] for k in fields & row.keys() if row[k]));opened=oracle('F',recipe['fieldPassword'].encode(),[v.encode() for v in values]);mapping={}
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        for value,expected in zip(values,opened):
            raw=shared._base64(value,urlsafe=True);actual=shared.rotate_java(unpad(AES.new(key,AES.MODE_CBC,raw[:16]).decrypt(raw[16:]),16).decode());assert actual==expected.decode();mapping[value]=actual
        count=0
        for row in obj[section]:
            for k in fields & row.keys():
                if row[k]:row[k]=mapping[row[k]];count+=1
        private(d/(name+'-decoded.json'),(json.dumps(obj,ensure_ascii=False,indent=2)+'\n').encode());reports.append({'source':name,'sha256':hashlib.sha256(data).hexdigest(),'version':obj['Version'],'section':section,'rows':len(obj[section]),'encryptedFields':count,'uniqueEncryptedFields':len(values),'wholeJcaEqual':True,'fieldNamesAndOccurrences':dict(names)})
    (d/'census-report.json').write_text(json.dumps(reports,indent=2)+'\n');print(json.dumps([{k:v for k,v in x.items() if k!='fieldNamesAndOccurrences'} for x in reports]))
if __name__=='__main__':main()
