#!/usr/bin/env python3
"""Full MM JSON parity: independent libsodium KDF/JDK GCM, CLI and worker.

Only counts/booleans are printed. Real catalogs and profiles stay outside Git.
"""
from __future__ import annotations
import argparse
import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from decoders.Python.apps.MM_Tunnel import codec,file_decoder,server_catalog_decoder


def reference():
    spec=importlib.util.spec_from_file_location('mm_reference',ROOT/'tests/golden/mm_tunnel_reference.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def independent_document(ref,wire):
    text=wire.decode('utf-8-sig').strip()
    if not text.startswith('{'):
        text=ref.open_many([(text,len(text.replace('\r','').replace('\n',''))%4==1)])[0]
    obj=json.loads(text)
    # Independently transcribed source contexts. Info is displayed directly;
    # URI is Boolean; unknown metadata never enters the field decryptor.
    root=('DefOVPNUser','DefOVPNPass','HysteriaUser','HysteriaOBFS','DefaultOVPNCert')
    server=('ServerIPHost','OVPNUser','OVPNPass','UDP_obfs','UDP_user','CustomCertificate',
            'SlowDNSHost','SlowDNSKey','V2rayUUID','V2rayPath','H2pass','TrojanPass')
    network=('Payload','CustomProxy','SNI','V2rayConfig','BugDNS','V2rayAddress','V2rayHost','V2raySNI')
    records=([(obj,network)] if 'Servers' not in obj else
             [(obj,root)]+[(s,server) for s in obj['Servers']]+[(n,network) for n in obj['Networks']])
    found={}
    for record,names in records:
        for name in names:
            x=record.get(name)
            if not isinstance(x,str):continue
            try:
                b=base64.b64decode(x,validate=True)
                if len(b)>=44:found[x]=None
            except (ValueError,UnicodeError):pass
    if found:
        found.update(zip(found,ref.open_many([(s,False) for s in found])))
    for record,names in records:
        for name in names:
            value=record.get(name)
            if isinstance(value,str) and value in found:record[name]=found[value]
    return obj,len(found)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog',type=Path)
    parser.add_argument('--file',type=Path)
    parser.add_argument('--worker',action='store_true')
    args=parser.parse_args();ref=reference()
    cases=[(x['kind'],x['wire'].encode(),x['expected']) for x in
           json.loads((ROOT/'tests/golden/mm_tunnel_vectors.json').read_text())['documents']]
    if args.catalog:cases.append(('catalog',args.catalog.read_bytes(),None))
    if args.file:cases.append(('file',args.file.read_bytes(),None))
    total_fields=0
    for kind,wire,expected in cases:
        independent,fields=independent_document(ref,wire);total_fields+=fields
        if expected is not None and independent!=expected:raise ValueError('Independent full golden mismatch')
        if args.worker:
            from cloud.workers.python.engine import decode_file,decode_provider_catalog
            result=(decode_file('mmt',wire) if kind=='file' else decode_provider_catalog('mm-tunnel',wire))
            if result['isPartial']:raise ValueError('Partial worker output')
            actual=result['structuredJson']
        else:
            actual=json.loads((file_decoder.run if kind=='file' else server_catalog_decoder.run)(wire))
        expected_full=({'application':'MM Tunnel','extension':'.mmt','config':independent}
                       if kind=='file' else independent)
        if actual!=expected_full:raise ValueError('Independent full document mismatch')
        # CLI uses the same installed Python; stdout is captured, never logged.
        # Private catalogs already exercised the identical isolated worker CLI.
        if expected is not None:
            path=ROOT/'decoders/Python/apps/MM_Tunnel'/('file_decoder.py' if kind=='file' else 'server_catalog_decoder.py')
            r=subprocess.run([sys.executable,str(path),'-'],input=wire,capture_output=True,timeout=20)
            if r.returncode or json.loads(r.stdout)!=expected_full:raise ValueError('CLI full document mismatch')
    print(json.dumps({'independentCompleteDocuments':len(cases),'independentInnerFields':total_fields,
                      'isolatedWorker':args.worker,'privateCatalog':bool(args.catalog),'privateFile':bool(args.file)}))


if __name__=='__main__':main()
