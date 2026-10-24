#!/usr/bin/env python3
"""Render a simple Android VectorDrawable losslessly in geometry, at source size.

Accepts compiled AXML from an APK (retain it as provenance). Only flat paths
with literal colors are supported; refuse groups, themes, gradients and clips.
Cairo antialiasing can differ from Android. No generated/reconstructed branding.
"""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path
import re
import xml.etree.ElementTree as ET

ANDROID='{http://schemas.android.com/apk/res/android}'


def render(raw: bytes) -> bytes:
    import cairosvg
    from loguru import logger
    logger.remove()
    from androguard.core.axml import AXMLPrinter
    root=ET.fromstring(AXMLPrinter(raw).get_xml())
    if root.tag!='vector' or set(root.attrib)!={ANDROID+x for x in ('height','width','viewportWidth','viewportHeight')}:
        raise ValueError('Unsupported vector root')
    def dimension(name):
        value=root.get(ANDROID+name)
        if not re.fullmatch(r'[0-9]+(?:\.[0-9]+)?(?:dip|dp)?',value):raise ValueError('Invalid dimension')
        return float(re.sub(r'dip$|dp$','',value))
    width,height=dimension('width'),dimension('height')
    if width!=int(width) or height!=int(height) or not 1<=width<=4096 or not 1<=height<=4096:
        raise ValueError('Unsupported size')
    svg=ET.Element('svg',{'xmlns':'http://www.w3.org/2000/svg','width':str(int(width)),
        'height':str(int(height)),'viewBox':f"0 0 {dimension('viewportWidth')} {dimension('viewportHeight')}"})
    permitted={'pathData','fillColor','fillAlpha','strokeColor','strokeAlpha','strokeWidth'}
    for item in root:
        attrs={k.removeprefix(ANDROID):v for k,v in item.attrib.items()}
        if item.tag!='path' or set(attrs)-permitted or 'pathData' not in attrs:
            raise ValueError('Unsupported vector child')
        target={'d':attrs['pathData']}
        for name,out,alpha in (('fillColor','fill','fillAlpha'),('strokeColor','stroke','strokeAlpha')):
            color=attrs.get(name,'#00000000')
            if not re.fullmatch(r'#[0-9a-fA-F]{8}',color):raise ValueError('Nonliteral color')
            target[out]='#'+color[3:]
            opacity=int(color[1:3],16)/255*float(attrs.get(alpha,'1'))
            if not 0<=opacity<=1:raise ValueError('Invalid alpha')
            target[out+'-opacity']=str(opacity)
        stroke=float(attrs.get('strokeWidth','0'))
        if stroke<0:raise ValueError('Invalid stroke width')
        target['stroke-width']=str(stroke)
        ET.SubElement(svg,'path',target)
    return cairosvg.svg2png(bytestring=ET.tostring(svg),output_width=int(width),output_height=int(height))


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('input',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    if a.output.exists():p.error('Output already exists')
    raw=a.input.read_bytes()
    if len(raw)>4*1024*1024:p.error('Vector exceeds limit')
    image=render(raw)
    with a.output.open('xb') as out:out.write(image)
    print(f'PNG bytes={len(image)} sha256={hashlib.sha256(image).hexdigest()}')


if __name__=='__main__':main()
