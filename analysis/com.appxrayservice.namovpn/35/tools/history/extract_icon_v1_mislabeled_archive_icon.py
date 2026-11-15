#!/usr/bin/env python3
"""Copy the original PNG carried in the exact XAPK, without re-encoding."""
import argparse,hashlib,io,json,zipfile
from pathlib import Path
from PIL import Image
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('bundle',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    assert hashlib.sha256(a.bundle.read_bytes()).hexdigest()=='d97d9f0625f5aecc6641569df709dc32f72a51015f0c3273a92d3e5526290fb1'
    with zipfile.ZipFile(a.bundle) as z:
        assert z.namelist().count('icon.png')==1;b=z.read('icon.png')
    assert hashlib.sha256(b).hexdigest()=='4d7ed99a87670b7c28b0b0552ed053420395d635317531cf0af1783396d05b0f'
    im=Image.open(io.BytesIO(b));assert im.format=='PNG' and im.size==(512,512)
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_bytes(b)
    print(json.dumps({'source':'XAPK/icon.png','bytes':len(b),'size':im.size,'unchanged':True}))
if __name__=='__main__':main()
