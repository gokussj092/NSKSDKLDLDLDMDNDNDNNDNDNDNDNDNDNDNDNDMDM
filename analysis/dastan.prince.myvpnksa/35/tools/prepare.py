#!/usr/bin/env python3
"""Unpack the pinned mirror XAPK, inspect the base and preserve original inputs."""
import argparse,hashlib,subprocess,sys,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from scripts.apk_analysis.inspect_apk import safe_read,write

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('xapk',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    assert hashlib.sha256(a.xapk.read_bytes()).hexdigest()=='9bf63096a5443dcaa61a5b0135f2c46604f7bd1c86e1770e4f153a6d4ec3c6aa'
    if a.output.exists() and any(a.output.iterdir()):p.error('Output must be empty')
    a.output.mkdir(parents=True,exist_ok=True,mode=0o700)
    with zipfile.ZipFile(a.xapk) as z:
        for name in z.namelist():
            if '/' not in name and name.endswith('.apk'):write(a.output/'apks'/name,safe_read(z,name))
    base=a.output/'apks/dastan.prince.myvpnksa.apk'
    subprocess.run([sys.executable,str(ROOT/'scripts/apk_analysis/inspect_apk.py'),str(base),str(a.output/'inspected')],check=True)
    with zipfile.ZipFile(base) as z:
        for name in ('gremlin.json','server.psi'):write(a.output/name,safe_read(z,'assets/'+name))
    with zipfile.ZipFile(a.output/'apks/config.arm64_v8a.apk') as z:
        write(a.output/'libputils.so',safe_read(z,'lib/arm64-v8a/libputils.so'))
if __name__=='__main__':main()
