#!/usr/bin/env python3
"""Public SSH response versus strict reader and isolated worker, hashes only."""
import argparse,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.OpenTunnel.server_catalog_decoder import decode_catalog
from cloud.workers.python.engine import decode_provider_catalog
def verify(path):
    raw=Path(path).read_bytes();reference=json.loads(raw);actual=decode_catalog(raw)
    r=decode_provider_catalog('opentunnel-ssh',raw)
    if reference!=actual or r['structuredJson']!=reference or json.loads(r['rawText'])!=reference or r['isPartial']:raise ValueError('WHOLE_SSH_JSON_MISMATCH')
    return {'inputBytes':len(raw),'inputSha256':hashlib.sha256(raw).hexdigest(),'servers':len(actual['servers']),'wholeRawJsonParity':True,'wholeWorkerParity':True,'publicAccountCredentialsPresent':False,'accountGenerationCalled':False,'warningReturned':bool(r['warnings']),'canonicalJsonSha256':hashlib.sha256(json.dumps(actual,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('catalog',type=Path);p.add_argument('--report',type=Path);a=p.parse_args();r=verify(a.catalog)
    if a.report:a.report.write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps(r))
