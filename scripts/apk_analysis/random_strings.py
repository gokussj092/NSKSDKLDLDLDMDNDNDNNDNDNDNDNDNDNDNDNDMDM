#!/usr/bin/env python3
"""Resolve explicit Java Random/long-array string literals from JADX, offline."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re


def decrypt(expr: str) -> str:
    nums=[int(x.strip().removesuffix('L')) for x in expr.split(',')]
    if not nums or any(not -(1<<63)<=n<(1<<63) for n in nums):raise ValueError('Invalid Java long array')
    mask=(1<<48)-1;state=(nums[0]^0x5deece66d)&mask
    def next_int():
        nonlocal state
        state=(state*0x5deece66d+11)&mask;v=state>>16
        return v-(1<<32) if v>>31 else v
    out=bytearray()
    for n in nums[1:]:
        rand=((next_int()<<32)+next_int())&((1<<64)-1)
        out.extend(((n&((1<<64)-1))^rand).to_bytes(8,'little'))
    return out.rstrip(b'\0').decode('utf-8')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('source',type=Path);p.add_argument('class_name',help='Confirmed obfuscator constructor, e.g. C1682lA')
    p.add_argument('output',type=Path);a=p.parse_args()
    source=a.source.resolve();out=a.output.resolve()
    if source==out or source in out.parents or out in source.parents:p.error('Directories must be separate, without nesting')
    rx=re.compile(r'new '+re.escape(a.class_name)+r'\(new long\[\]\{([\s\d,L-]+)\}\)\.toString\(\)')
    out.mkdir(parents=True,exist_ok=True,mode=0o700);count=0;files=0
    for f in source.rglob('*.java'):
        s=f.read_text('utf-8');matches=list(rx.finditer(s))
        if not matches:continue
        target=out/f.relative_to(source);target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        target.write_text(rx.sub(lambda m:json.dumps(decrypt(m[1]),ensure_ascii=True),s),'utf-8');target.chmod(0o600)
        count+=len(matches);files+=1
    if not count:raise ValueError('No supported literal expressions found')
    print(json.dumps({'resolvedStrings':count,'sourceFiles':files}))

if __name__=='__main__':main()
