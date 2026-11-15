#!/usr/bin/env python3
"""Decode literal P60 long arrays using transcribed java.util.Random arithmetic."""
import argparse,json,re,struct
from pathlib import Path
MASK=(1<<48)-1
def decode(values):
    state=(values[0]^0x5deece66d)&MASK
    def next32():
        nonlocal state
        state=(state*0x5deece66d+11)&MASK
        n=state>>16
        return n-(1<<32) if n&(1<<31) else n
    raw=b''
    for v in values[1:]:
        rnd=((next32()<<32)+next32())&((1<<64)-1)
        raw+=struct.pack('<Q',(v^rnd)&((1<<64)-1))
    return raw.rstrip(b'\0').decode('utf-8')
PATTERN=re.compile(r'new P60\(new long\[\]\{([\dL,\s-]+)\}\)\.toString\(\)')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('source',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    count=0
    for f in a.source.rglob('*.java'):
        text=f.read_text()
        if not PATTERN.search(text):continue
        def replace(m):
            global count
            count+=1
            return json.dumps(decode([int(x.strip().removesuffix('L')) for x in m[1].split(',')]))
        out=a.output/f.relative_to(a.source);out.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        out.write_text(PATTERN.sub(replace,text))
    print(json.dumps({'resolvedStrings':count}))
