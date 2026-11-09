#!/usr/bin/env python3
"""Offline .tnl reader: file path or --stdin. No cloud lookup or account calls."""
import argparse,sys
from pathlib import Path
if not __package__:sys.path.insert(0,str(Path(__file__).resolve().parents[4]))
from decoders.Python.apps.OpenTunnel.file_codec import MAX_INPUT,run
def main():
    p=argparse.ArgumentParser();p.add_argument('file',nargs='?',type=Path);p.add_argument('--stdin',action='store_true');a=p.parse_args()
    if bool(a.file)==a.stdin:p.error('Elige archivo o --stdin.')
    try:
        if a.file:
            with a.file.open('rb') as f:data=f.read(MAX_INPUT+1)
        else:data=sys.stdin.buffer.read(MAX_INPUT+1)
        print(run(data));return 0
    except (ValueError,OSError):print('Archivo OpenTunnel inválido o no compatible.',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
