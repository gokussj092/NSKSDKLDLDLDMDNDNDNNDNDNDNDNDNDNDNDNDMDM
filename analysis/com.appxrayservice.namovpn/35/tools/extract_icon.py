#!/usr/bin/env python3
"""Copy the original launcher PNG from the exact base APK in the XAPK, without re-encoding."""
import argparse,hashlib,io,json,zipfile
from pathlib import Path
from PIL import Image
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('bundle',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    assert hashlib.sha256(a.bundle.read_bytes()).hexdigest()=='d97d9f0625f5aecc6641569df709dc32f72a51015f0c3273a92d3e5526290fb1'
    with zipfile.ZipFile(a.bundle) as z:
        assert z.namelist().count('com.appxrayservice.namovpn.apk')==1
        base=z.read('com.appxrayservice.namovpn.apk')
    with zipfile.ZipFile(io.BytesIO(base)) as z:
        b=z.read('res/mipmap-xxxhdpi-v4/ic_launcher.png')
    im=Image.open(io.BytesIO(b));assert im.format=='PNG' and im.size==(192,192)
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_bytes(b)
    print(json.dumps({'source':'base.apk/res/mipmap-xxxhdpi-v4/ic_launcher.png','bytes':len(b),'size':im.size,'unchanged':True}))
if __name__=='__main__':main()
