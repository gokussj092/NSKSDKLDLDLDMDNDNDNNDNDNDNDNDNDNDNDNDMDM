"""Tx build-70 reference: libsodium Argon2id + JDK GCM; no production imports."""
from __future__ import annotations
import base64
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from tests.golden.mm_tunnel_reference import kdf,aes_batch

PASSWORD=b'TXTunnel2026@Pass'

def seal(text,counter=0):
    salt=bytes((i+counter)%256 for i in range(16));nonce=bytes((i+counter+73)%256 for i in range(12))
    line='\t'.join(['E',kdf(PASSWORD,salt).hex(),salt.hex(),nonce.hex(),base64.b64encode(text.encode()).decode()])
    return base64.b64encode(salt+nonce+aes_batch([line])[0]).decode()

def open_many(values):
    lines=[]
    for text,exported in values:
        if exported:raise ValueError('Tx has no inserted Base64 letter')
        raw=base64.b64decode(text.replace('\r','').replace('\n',''),validate=True)
        lines.append('\t'.join(['D',kdf(PASSWORD,raw[:16]).hex(),raw[:16].hex(),raw[16:28].hex(),base64.b64encode(raw[28:]).decode()]))
    return [b.decode() for b in aes_batch(lines)]

def generate():
    profile={'Name':'Tx 日本語','TunnelType':'SSH','Payload':seal('GET / HTTP/1.1\r\nHost: example.invalid\r\n',1),
             'CustomProxy':seal('proxy.example.invalid',2),'SNI':'plain.example.invalid','ProxyPort':'8080',
             'unknown':{'types':[False,None,0,42.5],'json':'{"keep":"string"}'},'security':{'password':'synthetic metadata','HWID':'test'}}
    expected=dict(profile,Payload='GET / HTTP/1.1\r\nHost: example.invalid\r\n',CustomProxy='proxy.example.invalid')
    catalog={'Version':'70.0','ReleaseNotes':'synthetic','Servers':[{'Name':'server','ServerIPHost':seal('vpn.example.invalid',3)}],
             'Networks':[profile],'DefOVPNPass':seal('',4)}
    expected_catalog=dict(catalog,Servers=[{'Name':'server','ServerIPHost':'vpn.example.invalid'}],Networks=[expected],DefOVPNPass='')
    documents=[]
    for kind,outer,clear in [('file',profile,expected),('catalog',catalog,expected_catalog)]:
        text=json.dumps(outer,ensure_ascii=False,separators=(',',':'))
        for mode in ['eo','plain']:
            documents.append({'kind':kind,'mode':mode,'wire':seal(text,10+len(documents)) if mode=='eo' else text,
                              'outer':outer,'expected':clear})
    return {'documents':documents,'duplicate':seal('{"Name":"a","TunnelType":"SSH","Name":"b"}',30)}

if __name__=='__main__':print(json.dumps(generate(),ensure_ascii=False,indent=2))
