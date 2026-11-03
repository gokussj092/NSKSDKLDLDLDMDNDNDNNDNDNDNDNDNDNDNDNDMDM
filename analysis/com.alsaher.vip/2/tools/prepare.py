#!/usr/bin/env python3
"""Reproduce fixed user-supplied APK acquisition/inspection; never execute APK/SO."""
import argparse,hashlib,json,subprocess,sys,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
SOURCE='https://archive.org/download/ALSAHERVIP/ALSAHERVIP.apk'
SHA256='5b68209e3d4a9f4703d678dedeaa07f00663fa9aaa279360b437db7976432a1a'

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('private_dir',type=Path);p.add_argument('--download',action='store_true')
    p.add_argument('--inspect',action='store_true');a=p.parse_args()
    a.private_dir.mkdir(parents=True,exist_ok=True,mode=0o700)
    apk=a.private_dir/'ALSAHERVIP.apk'
    if a.download:
        subprocess.run(['curl','--silent','--show-error','--location','--fail','--max-time','180',SOURCE,'--output',str(apk)],check=True)
    digest=hashlib.sha256(apk.read_bytes()).hexdigest()
    if digest!=SHA256:raise ValueError('APK changed; offsets/recipe must be reviewed')
    apk.chmod(0o600)
    with zipfile.ZipFile(apk) as z:
        if z.testzip() is not None:raise ValueError('Corrupt APK')
    if a.inspect:
        subprocess.run([sys.executable,str(ROOT/'scripts/apk_analysis/inspect_apk.py'),str(apk),
          str(a.private_dir/'inspected'),'--asset','mtkConfig.zip','--native','libh2.so'],check=True)
    asset=a.private_dir/'inspected/assets/mtkConfig.zip'
    if asset.exists():
        with zipfile.ZipFile(asset) as z:data=z.read('mtk.hs')
        path=a.private_dir/'mtk.hs';path.touch(mode=0o600,exist_ok=True);path.chmod(0o600);path.write_bytes(data)
    print(json.dumps({'apk_bytes':apk.stat().st_size,'apk_sha256':digest,'source':SOURCE}))
if __name__=='__main__':main()
