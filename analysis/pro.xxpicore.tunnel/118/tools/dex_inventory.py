#!/usr/bin/env python3
"""List application classes per DEX without exposing configuration strings."""
import argparse, json
from pathlib import Path
from androguard.core.dex import DEX
from loguru import logger

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory',type=Path)
    a=p.parse_args(); logger.remove()
    for f in sorted(a.directory.glob('classes*.dex')):
        names=[c.get_name() for c in DEX(f.read_bytes()).get_classes()]
        selected=[n for n in names if any(x in n.lower() for x in ('xxpicore','renz','encryption','xhypher','prine'))]
        print(json.dumps({'dex':f.name,'classes':len(names),'selected':selected}))

if __name__=='__main__': main()
