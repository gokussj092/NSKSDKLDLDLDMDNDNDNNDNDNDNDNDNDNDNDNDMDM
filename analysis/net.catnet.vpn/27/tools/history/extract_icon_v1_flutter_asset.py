#!/usr/bin/env python3
"""Copy original CATNET Flutter launcher artwork, verifying actual PNG content."""
import argparse,hashlib,io,json,zipfile
from pathlib import Path
from PIL import Image
ICON='assets/flutter_assets/assets/images/catnet_vpn_launcher_round.png'
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('apk',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    assert hashlib.sha256(a.apk.read_bytes()).hexdigest()=='995d5d9d70e0f929bd92e29125bf1c9ab87f6f8a3d064b6657c6d230d8e8b31a'
    with zipfile.ZipFile(a.apk) as z:data=z.read(ICON)
    assert data.startswith(b'\x89PNG\r\n\x1a\n')
    image=Image.open(io.BytesIO(data));image.verify();image=Image.open(io.BytesIO(data))
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_bytes(data)
    print(json.dumps({'source':ICON,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
        'dimensions':image.size,'conversion':False}))
if __name__=='__main__':main()
