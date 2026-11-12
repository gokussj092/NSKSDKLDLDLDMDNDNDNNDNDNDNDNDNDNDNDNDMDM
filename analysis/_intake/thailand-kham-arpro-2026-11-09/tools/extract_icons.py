#!/usr/bin/env python3
"""Convert original legacy launcher raster to PNG with identical RGBA pixels."""
import argparse,hashlib,json
from pathlib import Path
from PIL import Image
ROOT=Path(__file__).resolve().parents[4]
PROFILES={'thailand.vpn.globalvpn':('thailand-vpn','Thailand_VPN'),
          'com.khamvpn.net':('kham-vpn','KHAM_VPN'),
          'noob.arpro.vpn':('ar-pro-vpn','AR_Pro_VPN')}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args()
    for package,(identifier,decoder) in PROFILES.items():
        folder=a.private/package;candidates=[]
        for path in (folder/'splits').rglob('ic_launcher.*'):
            if path.suffix not in ('.png','.webp'):continue
            with Image.open(path) as image:candidates.append((image.width*image.height,path))
        _,source=max(candidates)
        with Image.open(source) as image:
            original=image.convert('RGBA');target=ROOT/'cloud/web/public/server-vpn-icons'/f'{identifier}.png'
            original.save(target,format='PNG')
            with Image.open(target) as png:assert png.convert('RGBA').tobytes()==original.tobytes()
        result=dict(source=str(source.relative_to(folder)),sourceSha256=hashlib.sha256(source.read_bytes()).hexdigest(),
          pngSha256=hashlib.sha256(target.read_bytes()).hexdigest(),width=original.width,height=original.height,pixelsEqual=True)
        (folder/'icon-summary.json').write_text(json.dumps(result,indent=2)+'\n');print(package,json.dumps(result))
