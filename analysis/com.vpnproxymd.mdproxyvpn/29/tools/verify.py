#!/usr/bin/env python3
"""Whole MD JSON via independent host libsodium + JCA, runtime and worker."""
import argparse,hashlib,json,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from tests.golden.ultra_tunnel_reference import catalog_reference
from decoders.Python.apps.MD_Proxy_VPN.codec import decode_catalog,run
def verify(path,worker=False):
    raw=Path(path).read_bytes();start=time.monotonic()
    reference,counts=catalog_reference(raw);actual=decode_catalog(raw)
    if reference!=actual:raise ValueError('WHOLE_INDEPENDENT_JSON_MISMATCH')
    result={'inputBytes':len(raw),'inputSha256':hashlib.sha256(raw).hexdigest(),'version':actual['Version'],'servers':len(actual['Servers']),'networks':len(actual['Networks']),**counts,'wholeIndependentParity':True,'rawOutputBytes':len(run(raw).encode()),'canonicalClearSha256':hashlib.sha256(json.dumps(actual,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest(),'apkCodeExecuted':False}
    if worker:
        from cloud.workers.python.engine import decode_provider_catalog
        r=decode_provider_catalog('md-proxy-vpn',raw)
        if r['structuredJson']!=reference or json.loads(r['rawText'])!=reference or r['isPartial']:raise ValueError('WHOLE_WORKER_JSON_MISMATCH')
        result['wholeWorkerParity']=True
    result['elapsedSeconds']=round(time.monotonic()-start,2)
    return result
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('catalog',type=Path);p.add_argument('--worker',action='store_true');p.add_argument('--report',type=Path);a=p.parse_args();r=verify(a.catalog,a.worker)
    if a.report:a.report.write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps(r),flush=True)
