#!/usr/bin/env python3
"""Compare complete CREEB VPN documents with JDK and worker; counts only."""
from __future__ import annotations
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from decoders.Python.apps.CREEB_VPN import codec
spec=importlib.util.spec_from_file_location('creeb_vpn_reference',ROOT/'tests/golden/creeb_vpn_generate.py')
reference=importlib.util.module_from_spec(spec);spec.loader.exec_module(reference)


def independent(data):
    text=data.decode('utf-8-sig').strip()
    doc=json.loads(text if text.startswith('{') else reference.oracle([('Cdec',text.encode())])[0])
    jobs=[];locations=[]
    for section,fields in (('Servers',reference.SERVER_FIELDS),('Tweaks',reference.TWEAK_FIELDS)):
        for row in doc.get(section,[]):
            key='S' if section=='Servers' or 'Custom Tweak' not in row.get('pInfo','') else 'C'
            for field in fields:
                if isinstance(row.get(field),str):
                    jobs.append((key+'dec',row[field].encode()));locations.append((row,field))
    for (row,field),plain in zip(locations,reference.oracle(jobs)):row[field]=plain.decode('utf-8')
    return doc


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--catalog',type=Path,action='append',default=[])
    p.add_argument('--file',type=Path,action='append',default=[])
    p.add_argument('--worker',action='store_true');a=p.parse_args()
    fixture=json.loads((ROOT/'tests/golden/creeb_vpn_vectors.json').read_text())
    entries=[(v['cipher'].encode(),v['name']=='catalog',v['expected']) for v in fixture['documents']]
    entries += [(path.read_bytes(),True,None) for path in a.catalog]
    entries += [(path.read_bytes(),False,None) for path in a.file]
    report={'documentsEqual':0,'workerEqual':0,'cliEqual':0,'realCatalogs':len(a.catalog),
            'realExports':len(a.file),'catalogCounts':[]}
    for data,is_catalog,expected in entries:
        actual=codec.decode(data,catalog=is_catalog)
        assert actual==independent(data)
        if expected is not None:assert actual==expected
        if is_catalog:report['catalogCounts'].append({'servers':len(actual['Servers']),'tweaks':len(actual['Tweaks'])})
        if a.worker:
            from cloud.workers.python.engine import decode_file,decode_provider_catalog
            result=decode_provider_catalog('creeb-vpn',data) if is_catalog else decode_file('crev',data)
            assert result['structuredJson']==actual==json.loads(result['rawText'])
            assert result['isPartial'] is False;report['workerEqual']+=1
        script='server_catalog_decoder.py' if is_catalog else 'file_decoder.py'
        proc=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/CREEB_VPN'/script),'-'],
                            input=data,capture_output=True,cwd='/tmp',check=True,timeout=20)
        assert json.loads(proc.stdout)==actual;report['cliEqual']+=1;report['documentsEqual']+=1
    print(json.dumps(report))


if __name__=='__main__':main()
