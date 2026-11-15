#!/usr/bin/env python3
"""Inventory/unpack only the selected XXPICore bundle, then inspect its exact base."""
import argparse,hashlib,json,subprocess,sys,zipfile
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from scripts.apk_analysis.inspect_apk import safe_read,write,relative
PACKAGE='pro.xxpicore.tunnel'
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('bundle',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    if a.output.exists() and any(a.output.iterdir()):p.error('Output must be empty')
    a.output.mkdir(parents=True,exist_ok=True,mode=0o700)
    if a.bundle.stat().st_size>150*1024*1024:raise ValueError('Oversized bundle')
    with zipfile.ZipFile(a.bundle) as z:
        names=[n for n in z.namelist() if '/' not in n and n.endswith('.apk')]
        if sum(z.getinfo(n).file_size for n in names)>300*1024*1024:raise ValueError('Oversized APK set')
        for name in names:write(a.output/'apks'/name,safe_read(z,name))
    base=a.output/'apks'/ (PACKAGE+'.apk')
    subprocess.run([sys.executable,str(ROOT/'scripts/apk_analysis/inspect_apk.py'),str(base),str(a.output/'inspected')],check=True)
    meta=json.loads((a.output/'inspected/metadata.json').read_text());assert meta['package']==PACKAGE and meta['versionCode']=='118'
    entries=[]
    for apk in (a.output/'apks').glob('*.apk'):
        with zipfile.ZipFile(apk) as z:
            selected=[n for n in z.namelist() if n.startswith('assets/') and not n.endswith('/') or n.startswith('lib/arm64-v8a/') and n.endswith('.so')]
            if sum(z.getinfo(n).file_size for n in selected)>150*1024*1024:raise ValueError('Oversized asset set')
            for name in selected:
                b=safe_read(z,name);target=a.output/'extracted'/apk.stem/relative(name);write(target,b)
                entries.append({'apk':apk.name,'path':name,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
    report={'bundleBytes':a.bundle.stat().st_size,'bundleSha256':hashlib.sha256(a.bundle.read_bytes()).hexdigest(),
      'metadata':meta,'entries':entries}
    write(a.output/'inventory.json',(json.dumps(report,indent=2)+'\n').encode())
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
