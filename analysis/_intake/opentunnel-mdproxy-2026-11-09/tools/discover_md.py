#!/usr/bin/env python3
"""Inspect fixed public distribution/publisher pages, never execute downloads."""
import argparse,hashlib,json
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin,urlsplit
from urllib.request import Request,urlopen
PAGES={'dog':'https://md-proxy-vpn.apk.dog/','uptodown':'https://md-proxy-vpn.en.uptodown.com/android/download','telegram':'https://t.me/s/mdproxyvpn?q=apk'}
class Links(HTMLParser):
    def __init__(self):super().__init__();self.links=[]
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=='a' and 'href' in a:self.links.append(a['href'])
def discover(source,folder):
    url=PAGES[source];folder=Path(folder);folder.mkdir(parents=True,exist_ok=True,mode=0o700)
    with urlopen(Request(url,headers={'User-Agent':'Mozilla/5.0','Accept-Encoding':'identity'}),timeout=25) as r:
        raw=r.read(2*1024*1024+1);status=r.status
    if len(raw)>2*1024*1024:raise ValueError('PAGE_BOUNDS')
    p=folder/(source+'.html');p.write_bytes(raw);p.chmod(0o600)
    parser=Links();parser.feed(raw.decode('utf-8'))
    links=[urljoin(url,x) for x in parser.links if any(s in x.lower() for s in ['down','apk','version','/mdproxyvpn'])]
    result={'source':url,'status':status,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'links':list(dict.fromkeys(links))[:50]}
    (folder/(source+'-discovery.json')).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('source',choices=PAGES);p.add_argument('private',type=Path);a=p.parse_args();discover(a.source,a.private)
