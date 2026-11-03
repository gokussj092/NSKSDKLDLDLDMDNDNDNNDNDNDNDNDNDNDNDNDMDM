#!/usr/bin/env python3
"""Convert the original highest-density legacy launcher WebP to PNG, no resize."""
import argparse
import hashlib
import io
from pathlib import Path
import zipfile
from PIL import Image

BASE_SHA256 = 'bd5a259b37427914a44a3e49f7ad4f9a8b22823285f6dc9d94f4e809036b8aac'
SOURCE = 'res/mipmap-xxxhdpi-v4/ic_launcher.webp'

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('apk', type=Path)
    p.add_argument('png', type=Path)
    a = p.parse_args()
    if hashlib.sha256(a.apk.read_bytes()).hexdigest() != BASE_SHA256:
        raise ValueError('Wrong source APK')
    with zipfile.ZipFile(a.apk) as z: data = z.read(SOURCE)
    image = Image.open(io.BytesIO(data)).convert('RGBA')
    a.png.parent.mkdir(parents=True, exist_ok=True)
    image.save(a.png, format='PNG')
    reopened = Image.open(a.png).convert('RGBA')
    if reopened.size != image.size or reopened.tobytes() != image.tobytes():
        raise ValueError('Icon conversion changed source pixels')
    print({'source': SOURCE, 'source_sha256': hashlib.sha256(data).hexdigest(),
           'width': image.width, 'height': image.height,
           'png_bytes': a.png.stat().st_size, 'png_sha256': hashlib.sha256(a.png.read_bytes()).hexdigest()})

if __name__ == '__main__': main()
