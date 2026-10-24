#!/usr/bin/env python3
"""Tx .tx reader with complete inner fields and authenticated historical fallback."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from decoders.Python.apps.Tx_Tunnel import codec
from decoders.Python import ultra

def run(data:bytes)->str:
    codec.input_text(data)
    try:outer=codec.open_document(data)
    except codec.DecodeError as error:
        if str(error)!='INVALID_AUTHENTICATED_ENVELOPE':raise
        outer=None
    if outer is not None and ('Name' in outer or 'TunnelType' in outer):
        if not all(isinstance(outer.get(k),str) for k in ('Name','TunnelType')):
            raise codec.DecodeError('INVALID_TX_PROFILE')
        # Do not retry the permissive legacy reader after an inner tag failure:
        # both generations share a key, so that would hide encrypted fields.
        config=codec.decode_fields(outer)
    else:
        config=ultra.decrypt_ultra_file(data,'.tx')
        if config is None:raise codec.DecodeError('INVALID_TX_PROFILE')
    return codec.render({'application':ultra.ULTRA_NAMES['.tx'],'extension':'.tx','config':config})

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('file',help='Profile path, or - for stdin');a=p.parse_args()
    try:
        if a.file=='-':data=sys.stdin.buffer.read(codec.MAX_BYTES+1)
        else:
            with Path(a.file).open('rb') as f:data=f.read(codec.MAX_BYTES+1)
        print(run(data));return 0
    except (ValueError,OSError,RecursionError):
        print('No se pudo leer el archivo Tx Tunnel completo.',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
