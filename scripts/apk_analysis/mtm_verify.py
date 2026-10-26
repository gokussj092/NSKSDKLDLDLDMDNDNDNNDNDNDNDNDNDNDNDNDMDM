#!/usr/bin/env python3
"""Compare whole private MTM catalogs against independent JDK and offline workers."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from decoders.Python.apps.MTM_Tunnel_Lite import codec


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('files',nargs='+',type=Path)
    parser.add_argument('--worker',action='store_true')
    args=parser.parse_args()
    try:
        for path in args.files:
            data=codec.read_input(str(path))
            plain=codec.decode_bytes(data);doc=codec.parse_catalog(plain)
            reference=subprocess.run(['java',str(ROOT/'tests/golden/mtm_oracle.java'),str(path)],
                capture_output=True,check=True,timeout=40).stdout
            if plain!=reference:raise ValueError('Complete JDK bytes differ')
            if args.worker:
                from cloud.workers.python.engine import decode_provider_catalog,decode_file
                for result in (decode_provider_catalog('mtm-tunnel-lite',data),decode_file('v2',data)):
                    if result['isPartial'] or result['structuredJson']!=doc or json.loads(result['rawText'])!=doc:
                        raise ValueError('Complete worker JSON differs')
            print(json.dumps({'version':doc['Version'],'plaintextBytes':len(plain),
                'servers':{name:len(doc.get(name,[])) for name in ('Free_servers','Premium_servers','Vip_servers','Private_servers')},
                'payloads':len(doc['Payloads']),'jdkCompleteMatch':True,'workerCompleteMatch':args.worker}))
    except (ValueError,OSError,subprocess.SubprocessError,RecursionError):
        print('No se pudo verificar el documento MTM completo; no se muestran datos privados.',file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
