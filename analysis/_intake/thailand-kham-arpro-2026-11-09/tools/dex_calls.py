#!/usr/bin/env python3
"""Locate method references without executing APK code; private disassembly."""
import argparse,re,zipfile
from pathlib import Path
from androguard.core.dex import DEX
from loguru import logger
logger.disable('androguard')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('apk',type=Path);p.add_argument('pattern');p.add_argument('output',type=Path);a=p.parse_args()
    out=[]
    with zipfile.ZipFile(a.apk) as z:
        for n in z.namelist():
            if not re.fullmatch(r'classes\d*\.dex',n):continue
            for c in DEX(z.read(n)).get_classes():
                for m in c.get_methods():
                    rows=[i.get_name()+' '+i.get_output() for i in m.get_instructions()]
                    if any(a.pattern in row for row in rows):out.append(c.get_name()+' '+m.get_name()+'\n'+'\n'.join(rows))
    a.output.write_text('\n\n'.join(out),errors='backslashreplace');print('matched methods:',len(out))
