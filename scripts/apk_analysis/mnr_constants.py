#!/usr/bin/env python3
"""Recover build-31 Java shift constants from exact JADX sources, not the APK runtime."""
import argparse
import json
from pathlib import Path
import re

def recover(root):
    values=[]
    for name in ('p072k4/c.java','G4/f.java'):
        text=(root/name).read_text('utf-8')
        lines=[line for line in text.splitlines() if 'return new String(new byte[]{' in line]
        if len(lines)!=1:raise ValueError('Ambiguous string constructor')
        numbers=re.findall(r'(-?\d+)\)? >>> A\.i\.e',lines[0])
        # A.i.e(Integer.valueOf(new String({(byte)822,(byte)4791865})))
        # = parseInt("69"); Java int shift distance is masked by 31.
        values.append(bytes(((int(n)&0xffffffff)>>(69&31))&255 for n in numbers).decode('utf-8'))
    if [len(v.encode('utf-8')) for v in values]!=[48,31]:raise ValueError('Unexpected build constants')
    return {'fieldAlphabet':values[0],'fieldSecret':values[1]}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('sources',type=Path);a=p.parse_args()
    print(json.dumps(recover(a.sources),ensure_ascii=True))

if __name__=='__main__':main()
