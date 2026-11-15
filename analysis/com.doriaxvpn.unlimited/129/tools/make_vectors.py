#!/usr/bin/env python3
"""Generate fictional glyph/CBC and GCM fields using the independent JCA oracle."""
import base64,json,subprocess,sys,textwrap
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.HTTP_Conexion.codec import CATALOG_PASSWORD,FIELD_KEY
def transform(mode,values,key):
    lines=''.join(mode+'\t'+base64.b64encode(key).decode()+'\t'+base64.b64encode(v).decode()+'\n' for v in values)
    done=subprocess.run(['java',str(Path(__file__).with_name('CatalogOracle.java'))],input=lines,
      text=True,capture_output=True,check=True,timeout=45)
    out=[base64.b64decode(x,validate=True) for x in done.stdout.splitlines()]
    if len(out)!=len(values):raise ValueError('Incomplete Java reference')
    return out
def seal(doc):return transform('E',[json.dumps(doc,ensure_ascii=False,separators=(',',':')).encode()],CATALOG_PASSWORD)[0]
def main():
    expected={'Version':'test129','ReleaseNotes':'Fictional prueba ñ ไทย 🦊',
      'Servers':[{'Name':'Fictional HTTP profile','FLAG':'mx','ServerIP':'vpn.example.org','ServerPort':'443',
        'ServerUser':'sample-user','ServerPass':'sample-password','Payload':'CONNECT [host_port] HTTP/1.1\r\nHost: example.org\r\n\r\n',
        'SNI':'front.example.org','UseTcp':'TCP','udpObfs':'','v2rayFlow':'xtls-rprx-vision',
        'zivpnPassword':'0123456789ABCDEFGHJKLMNPQRSTUVWXYZ','isSSL':True,'UnknownData':{'preserve':[1,None,False]}}]}
    wire=json.loads(json.dumps(expected));fields=json.loads((Path(__file__).resolve().parents[1]/'generated/protected-fields.json').read_text())
    row=wire['Servers'][0];names=[k for k in fields if k in row and row[k]]
    encrypted=transform('G',[row[k].encode() for k in names],FIELD_KEY)
    for name,value in zip(names,encrypted):row[name]='\n'.join(textwrap.wrap(value.decode(),76))+'\n'
    out=Path(__file__).resolve().parents[1]/'tests/fixtures';out.mkdir(parents=True,exist_ok=True)
    (out/'expected.json').write_text(json.dumps(expected,ensure_ascii=False,indent=2)+'\n')
    (out/'wire.json').write_text(json.dumps(wire,ensure_ascii=False,indent=2)+'\n');(out/'catalog.txt').write_bytes(seal(wire))
if __name__=='__main__':main()
