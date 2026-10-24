#!/usr/bin/env python3
"""Existing RENZ .xhypher file route, including build-43 invisible credentials."""
from pathlib import Path
import argparse
import sys
if __package__:
    from .codec import DecodeError,MAX_BYTES,shared
else:
    from codec import DecodeError,MAX_BYTES,shared


def run(data: bytes) -> str:
    if not isinstance(data,bytes) or not data or len(data)>MAX_BYTES:
        raise DecodeError('Perfil vacío o superior a 8 MiB.')
    value=shared.decode_file(data,'.xhypher')
    if not value:
        raise DecodeError('Perfil Xhypher inválido.')
    return value


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('file',nargs='?',type=Path);a=p.parse_args()
    try:
        if a.file:
            with a.file.open('rb') as stream:data=stream.read(MAX_BYTES+1)
        else:data=sys.stdin.buffer.read(MAX_BYTES+1)
        sys.stdout.write(run(data));return 0
    except (ValueError,OSError):
        print('No se pudo leer el perfil Xhypher.',file=sys.stderr);return 1


if __name__=='__main__':raise SystemExit(main())
