#!/usr/bin/env python3
"""Compare ZIP member hashes between authorized APK builds without execution."""
import argparse,hashlib,json,zipfile
from pathlib import Path
def compare(old,new):
    def index(path):
        with zipfile.ZipFile(path) as z:return {i.filename:hashlib.sha256(z.read(i)).hexdigest() for i in z.infolist()}
    a,b=index(old),index(new)
    return {'changedMembers':[{'path':p,'oldSha256':a.get(p),'newSha256':b.get(p)} for p in sorted(set(a)|set(b)) if a.get(p)!=b.get(p)],
        'unchangedMembers':sum(a.get(p)==v for p,v in b.items()),'apkCodeExecuted':False}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('old',type=Path);p.add_argument('new',type=Path);p.add_argument('--report',type=Path)
    a=p.parse_args();r=compare(a.old,a.new)
    if a.report:a.report.write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps(r))
