#!/usr/bin/env python3
"""Inspect only the observed ARM64 download page; no browser/app code execution."""
import argparse,hashlib,json
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.parse import urljoin
from html.parser import HTMLParser
SOURCE='https://apk.dog/download?split=604727/3533139/md-proxy-vpn'
class Links(HTMLParser):
    def __init__(self):super().__init__();self.links=[]
    def handle_starttag(self,t,attrs):
        a=dict(attrs)
        if t=='a' and 'href' in a:self.links.append(a['href'])
def discover(folder):
    folder=Path(folder)
    with urlopen(Request(SOURCE,headers={'User-Agent':'Mozilla/5.0','Accept-Encoding':'identity'}),timeout=25) as r:
        final=r.url;status=r.status;content_type=r.headers.get('Content-Type');data=r.read(125*1024*1024+1)
    if len(data)>125*1024*1024:raise ValueError('DOWNLOAD_BOUNDS')
    name='mirror-distribution.zip' if data.startswith(b'PK') else 'mirror-download.html';p=folder/name;p.write_bytes(data);p.chmod(0o600)
    result={'source':SOURCE,'final':final,'status':status,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'contentType':content_type,'archive':name.endswith('.zip')}
    if not result['archive']:
        parser=Links();parser.feed(data.decode());result['links']=[urljoin(final,s) for s in parser.links if any(x in s.lower() for x in ['download','apk','split'])][:40]
    (folder/'mirror-discovery.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();discover(a.private)
