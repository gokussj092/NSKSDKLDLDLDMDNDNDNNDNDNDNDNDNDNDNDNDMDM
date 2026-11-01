#!/usr/bin/env python3
"""Offline Enaa build7 .enaa reader; no device identity or external password."""
import json,sys
from pathlib import Path
if __package__:
    from .codec import decode_file,render,MAX_BYTES
else:
    from codec import decode_file,render,MAX_BYTES

def run(data):return render({'application':'Enaa Tunnel','extension':'.enaa','config':decode_file(data)})
def main():
    try:
        if len(sys.argv)>2:return 2
        if len(sys.argv)==2 and sys.argv[1] not in ('-','--stdin'):
            with Path(sys.argv[1]).open('rb') as stream:data=stream.read(MAX_BYTES+1)
        else:data=sys.stdin.buffer.read(MAX_BYTES+1)
        print(run(data));return 0
    except (ValueError,OSError,RecursionError):
        print('No se pudo leer el perfil Enaa completo.',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
