#!/usr/bin/env python3
"""Inspect the actual ELF in every packaged ABI, using readelf (host or LLVM)."""
import argparse
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile

def inspect(path,tool):
    run=lambda *args:subprocess.check_output([tool,*args,str(path)],text=True)
    headers=run('--wide','--program-headers');dynamic=run('--wide','--dynamic')
    symbols=run('--wide','--dyn-syms')
    stack=next((line for line in headers.splitlines() if 'GNU_STACK' in line),'')
    assert stack and not re.search(r'\bRWE\b',stack),'executable/missing GNU_STACK'
    assert 'GNU_RELRO' in headers,'missing RELRO'
    assert 'BIND_NOW' in dynamic or re.search(r'FLAGS_1.*\bNOW\b',dynamic),'missing immediate binding'
    assert 'TEXTREL' not in dynamic,'text relocations forbidden'
    for line in headers.splitlines():
        if line.strip().startswith('LOAD '):
            assert not re.search(r'\bRWE\b',line),'writable executable segment'
    exports=set()
    for line in symbols.splitlines():
        parts=line.split()
        if len(parts)>=8 and parts[4] in {'GLOBAL','WEAK'} and parts[5] in {'DEFAULT','PROTECTED'} and parts[6]!='UND':
            exports.add(parts[7].split('@')[0])
    assert exports=={'JNI_OnLoad'},f'unexpected public exports: {sorted(exports)}'

def main():
    p=argparse.ArgumentParser();p.add_argument('apk',type=Path);p.add_argument('--readelf',default=shutil.which('llvm-readelf') or shutil.which('readelf'))
    args=p.parse_args();assert args.readelf,'readelf required'
    with zipfile.ZipFile(args.apk) as z, tempfile.TemporaryDirectory() as d:
        names=[n for n in z.namelist() if re.fullmatch(r'lib/[^/]+/libv7q3\.so',n)]
        assert {n.split('/')[1] for n in names}>={'arm64-v8a','armeabi-v7a','x86','x86_64'},'ABI missing'
        for n in names:
            out=Path(d)/n.split('/')[1];out.write_bytes(z.read(n));inspect(out,args.readelf)
            print('PASS ELF '+n.split('/')[1]+': RELRO/NOW/NX, exports and no TEXTREL/W+X')
if __name__=='__main__':main()
