#!/usr/bin/env python3
"""Download original KHAM catalog and verify its envelope with Java oracle."""
import argparse,base64,hashlib,json,subprocess
from pathlib import Path
from urllib.request import Request,urlopen
ROOT=Path(__file__).resolve().parents[4]
SOURCE='https://pukangvpn.xyz/khamvpn/Config.json'
def probe(directory):
    with urlopen(Request(SOURCE,headers={'User-Agent':'okhttp/4.12.0','Accept-Encoding':'identity'}),timeout=30) as r:
        raw=r.read(8*1024*1024+1);status=r.status
    if status!=200 or not raw or len(raw)>8*1024*1024:raise ValueError('RESPONSE')
    (directory/'catalog.wire').write_bytes(raw)
    # Native getter b format constant, not an HTTP/user credential.
    key=b'khamvpn270@'
    line='D\t'+base64.b64encode(key).decode()+'\t'+base64.b64encode(raw).decode()+'\n'
    oracle=ROOT/'analysis/com.appxrayservice.namovpn/35/tools/CatalogOracle.java'
    r=subprocess.run(['java',str(oracle)],input=line,text=True,capture_output=True,check=True,timeout=60)
    plain=base64.b64decode(r.stdout.strip());doc=json.loads(plain)
    (directory/'oracle-outer.json').write_bytes(plain)
    result=dict(http=status,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
      topKeys=list(doc),version=doc.get('Version'),serverCount=len(doc.get('Servers',[])),networkCount=len(doc.get('Networks',[])))
    (directory/'probe-summary.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();probe(a.private)
