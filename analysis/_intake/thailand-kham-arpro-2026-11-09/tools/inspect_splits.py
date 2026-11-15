#!/usr/bin/env python3
"""Inventory split APKs and retain bounded native/icon bytes privately."""
import argparse,hashlib,json,zipfile,re
from io import BytesIO
from pathlib import Path

def inspect(directory):
    rows=[]
    with zipfile.ZipFile(directory/'distribution.xapk') as bundle:
        for entry in bundle.infolist():
            if not entry.filename.endswith('.apk') or entry.file_size>125*1024*1024:continue
            if Path(entry.filename).name!=entry.filename or entry.filename.startswith('.'):raise ValueError('UNSAFE_SPLIT')
            with zipfile.ZipFile(BytesIO(bundle.read(entry))) as apk:
                for item in apk.infolist():
                    name=item.filename
                    if item.file_size>50*1024*1024 or not (name.startswith('lib/') or re.search(r'(launcher|ic_icon|app_icon).*\.(png|webp)$',name)):continue
                    raw=apk.read(item);target=directory/'splits'/entry.filename/name
                    if '..' in Path(name).parts or Path(name).is_absolute():raise ValueError('UNSAFE_ENTRY')
                    target.parent.mkdir(parents=True,exist_ok=True,mode=0o700);target.write_bytes(raw)
                    rows.append(dict(split=entry.filename,path=name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
    (directory/'splits.json').write_text(json.dumps(rows,indent=2)+'\n')
    print(json.dumps(rows))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);a=p.parse_args();inspect(a.directory)
