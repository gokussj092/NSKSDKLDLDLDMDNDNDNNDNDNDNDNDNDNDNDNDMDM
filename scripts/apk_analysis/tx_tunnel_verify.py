#!/usr/bin/env python3
"""Full Tx JSON parity with independent libsodium/JDK, CLI and worker.

Prints only counts; accepts local private files, never arbitrary remote URLs.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tests.golden import tx_tunnel_reference as reference
from mm_tunnel_verify import independent_document
from decoders.Python.apps.Tx_Tunnel import file_decoder,server_catalog_decoder

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--catalog',action='append',type=Path,default=[])
    p.add_argument('--file',type=Path);p.add_argument('--worker',action='store_true');a=p.parse_args()
    cases=[(v['kind'],v['wire'].encode(),v['expected']) for v in json.loads((ROOT/'tests/golden/tx_tunnel_vectors.json').read_text())['documents']]
    cases.extend(('catalog',f.read_bytes(),None) for f in a.catalog)
    if a.file:cases.append(('file',a.file.read_bytes(),None))
    count=0;summaries=[]
    for kind,wire,golden in cases:
        expected,n=independent_document(reference,wire);count+=n
        if golden is not None and expected!=golden:raise ValueError('Golden full document mismatch')
        expected_full={'application':'TX TUNNEL','extension':'.tx','config':expected} if kind=='file' else expected
        if a.worker:
            from cloud.workers.python.engine import decode_file,decode_provider_catalog
            r=decode_file('tx',wire) if kind=='file' else decode_provider_catalog('tx-tunnel',wire)
            if r['isPartial'] or json.loads(r['rawText'])!=expected_full:raise ValueError('Partial or invalid worker JSON')
            actual=r['structuredJson']
        else:actual=json.loads((file_decoder.run if kind=='file' else server_catalog_decoder.run)(wire))
        if actual!=expected_full:raise ValueError('Independent full JSON mismatch')
        if golden is not None:
            script=ROOT/'decoders/Python/apps/Tx_Tunnel'/('file_decoder.py' if kind=='file' else 'server_catalog_decoder.py')
            r=subprocess.run([sys.executable,str(script),'-'],input=wire,capture_output=True,timeout=20)
            if r.returncode or json.loads(r.stdout)!=expected_full:raise ValueError('CLI mismatch')
        if golden is None and kind=='catalog':summaries.append({'version':expected['Version'],'servers':len(expected['Servers']),'networks':len(expected['Networks']),'fields':n})
    print(json.dumps({'completeIndependentDocuments':len(cases),'independentInnerFields':count,
                      'isolatedWorker':a.worker,'privateCatalogs':summaries,'privateFile':bool(a.file)}))

if __name__=='__main__':main()
