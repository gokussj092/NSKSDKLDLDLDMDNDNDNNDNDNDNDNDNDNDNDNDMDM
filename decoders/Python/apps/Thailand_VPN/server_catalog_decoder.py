#!/usr/bin/env python3
"""Thailand catalog CLI; offline run(), explicit --download follows Firebase."""
import argparse,sys
from pathlib import Path
if not __package__:sys.path.insert(0,str(Path(__file__).resolve().parents[4]))
from decoders.Python.apps.Thailand_VPN.codec import run,MAX_BYTES

def download():
    from decoders.Python.apps.Thailand_VPN.protocol import download as fetch
    return fetch()

def main():
    p=argparse.ArgumentParser();g=p.add_mutually_exclusive_group()
    g.add_argument('file',nargs='?',type=Path);g.add_argument('--stdin',action='store_true');g.add_argument('--download',action='store_true');a=p.parse_args()
    try:
        if a.file:
            with a.file.open('rb') as f:data=f.read(MAX_BYTES+1)
        elif a.stdin:data=sys.stdin.buffer.read(MAX_BYTES+1)
        else:data=download()
        print(run(data));return 0
    except (OSError,ValueError,RecursionError):
        print('No se pudo leer el catálogo Thailand VPN completo.',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
