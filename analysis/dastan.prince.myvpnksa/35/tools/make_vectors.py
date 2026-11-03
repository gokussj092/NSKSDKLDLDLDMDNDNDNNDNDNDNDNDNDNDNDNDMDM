#!/usr/bin/env python3
"""Create only fictional deterministic catalogs; never copy real VPN records."""
import base64,json,struct
from pathlib import Path

def seal(data):
    if isinstance(data,str):data=data.encode()
    v=list(struct.unpack('<'+'I'*((len(data)+3)//4),data.ljust((len(data)+3)//4*4,b'\0')))+[len(data)]
    k=struct.unpack('<4I',b'...|...'.ljust(16,b'\0'));mask=0xffffffff;z=v[-1];s=0
    for _ in range(6+52//len(v)):
        s=(s+0x9e5729b1)&mask;e=(s>>2)&3
        for p in range(len(v)):
            y=v[(p+1)%len(v)]
            mix=(((z>>5)^(y<<2))+((y>>3)^(z<<4)))^((s^y)+(k[(p&3)^e]^z))
            v[p]=(v[p]+mix)&mask;z=v[p]
    return base64.b64encode(struct.pack('<'+'I'*len(v),*v))

def main():
    doc={'Version':'test35','Free_servers':[{'friendly_name':'Fictional server','server_host':'vpn.example.org','server_port':'443'}],
      'Premium_servers':[],'Vip_servers':[],'Private_servers':[],
      'Payloads':[{'friendly_name':'Preserve plain hex','host':'80','payload':'deadbeef','sausage':'443'},
                  {'friendly_name':'Unicode','host':'sni.example.org','payload':'GET / HTTP/1.1\r\nHost: example.org\r\n\r\n','sausage':'prueba ñ 🦊'}],
      'Changelogs':'Fictional only','FutureMetadata':{'nested':[True,None,35]}}
    out=Path(__file__).resolve().parents[1]/'tests/fixtures';out.mkdir(parents=True,exist_ok=True)
    (out/'expected.json').write_text(json.dumps(doc,ensure_ascii=False,indent=2)+'\n')
    (out/'catalog.txt').write_bytes(seal(json.dumps(doc,ensure_ascii=False,separators=(',',':'))))
if __name__=='__main__':main()
