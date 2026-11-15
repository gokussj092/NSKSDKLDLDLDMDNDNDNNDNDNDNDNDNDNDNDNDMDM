#!/usr/bin/env python3
"""Unpack only the selected APK set, inventory assets and small custom ARM64 libs."""
import argparse,hashlib,json,subprocess,sys,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from scripts.apk_analysis.inspect_apk import safe_read,write,relative
PACKAGE='netfree.mx.anuncios'
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('bundle',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    if a.output.exists() and any(a.output.iterdir()):p.error('Output must be empty')
    if a.bundle.stat().st_size>250*1024*1024:raise ValueError('Oversized bundle')
    a.output.mkdir(parents=True,exist_ok=True,mode=0o700)
    with zipfile.ZipFile(a.bundle) as z:
        names=[n for n in z.namelist() if '/' not in n and n.endswith('.apk')]
        if sum(z.getinfo(n).file_size for n in names)>600*1024*1024:raise ValueError('Oversized APK set')
        for n in names:write(a.output/'apks'/n,safe_read(z,n))
    base=a.output/'apks'/ (PACKAGE+'.apk')
    if not base.exists():base=a.output/'apks/base.apk'
    subprocess.run([sys.executable,str(ROOT/'scripts/apk_analysis/inspect_apk.py'),str(base),str(a.output/'inspected')],check=True)
    meta=json.loads((a.output/'inspected/metadata.json').read_text());assert meta['package']==PACKAGE
    entries=[]
    for apk in (a.output/'apks').glob('*.apk'):
        with zipfile.ZipFile(apk) as z:
            selected=[n for n in z.namelist() if n.startswith('assets/') and not n.endswith('/') or n.startswith('lib/arm64-v8a/') and n.endswith('.so')]
            for n in selected:
                info=z.getinfo(n)
                entry={'apk':apk.name,'path':n,'bytes':info.file_size,'sha256':None}
                if info.file_size<=10*1024*1024:
                    b=safe_read(z,n);write(a.output/'extracted'/apk.stem/relative(n),b);entry['sha256']=hashlib.sha256(b).hexdigest()
                else:entry['note']='Large generic asset/library inventoried only, not extracted or executed.'
                entries.append(entry)
    report={'bundleBytes':a.bundle.stat().st_size,'bundleSha256':hashlib.sha256(a.bundle.read_bytes()).hexdigest(),
      'metadata':meta,'entries':entries}
    write(a.output/'inventory.json',(json.dumps(report,indent=2)+'\n').encode());print(json.dumps({k:v for k,v in report.items() if k!='entries'},indent=2))
if __name__=='__main__':main()
