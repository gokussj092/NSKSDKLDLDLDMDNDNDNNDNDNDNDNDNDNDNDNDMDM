#!/usr/bin/env python3
"""Use the existing reviewed LSParanoid arithmetic adapter on renamed KHAM data."""
import argparse,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args()
    source=a.private/'jadx/sources';original=source/'defpackage/j72.java'
    # Only normalize the data declaration for the shared parser. Never compile APK source.
    normalized=a.private/'j72-data.java'
    text=original.read_text();text=text.replace('String[] b = {','String[] b = new String[]{',1)
    normalized.write_text(text)
    subprocess.run([sys.executable,str(ROOT/'scripts/apk_analysis/paranoid_strings.py'),str(source),
      str(normalized),str(a.private/'resolved'),'--chunk-field','b','--method','q',
      '--call-class','j72','--inventory'],check=True)
