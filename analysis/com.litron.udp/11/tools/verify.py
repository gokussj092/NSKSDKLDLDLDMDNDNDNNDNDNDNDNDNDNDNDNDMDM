#!/usr/bin/env python3
"""Independent JCA whole JSON/inner fields versus Python and optional worker."""
import argparse,base64,hashlib,json,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.Litron_Pro_VPN import codec
# Separate contract copied from the observed Android consumers, not runtime FIELDS.
NATIVE_FIELDS={'ChaveKey','DNS','NameServer','Password','Payload','ProxyIP','SNI','ServerHost','Username'}
def oracle(jobs):
    with tempfile.TemporaryDirectory(prefix='litron-pro-jca-') as folder:
        p=Path(folder)/'commands.tsv'
        p.write_text(''.join(op+'\t'+base64.b64encode(seed).decode()+'\t'+base64.b64encode(raw).decode()+'\n' for op,seed,raw in jobs));p.chmod(0o600)
        r=subprocess.run(['java',str(Path(__file__).with_name('ProOracle.java')),str(p)],capture_output=True,timeout=60)
    if r.returncode:raise ValueError('INDEPENDENT_JCA_FAILED')
    lines=r.stdout.decode().splitlines()
    if len(lines)!=len(jobs):raise ValueError('INDEPENDENT_RESULT_COUNT')
    return [base64.b64decode(line,validate=True) for line in lines]
def cipher(value):return base64.b64decode(''.join(value.split()),validate=True)
def verify(path,worker=False):
    data=Path(path).read_bytes();reference=json.loads(oracle([('open',b'godtech25',cipher(data.decode('ascii')))])[0])
    targets=[];jobs=[]
    for server in reference['Servers']:
        for key in sorted(NATIVE_FIELDS.intersection(server)):
            if server[key]:targets.append((server,key));jobs.append(('open',bytes([32]*8),cipher(server[key])))
    for raw,(parent,key) in zip(oracle(jobs) if jobs else [],targets):parent[key]=raw.decode('utf-8')
    actual=codec.decode_catalog(data)
    if actual!=reference:raise ValueError('WHOLE_JCA_JSON_MISMATCH')
    result={'inputBytes':len(data),'inputSha256':hashlib.sha256(data).hexdigest(),'version':actual['Version'],'servers':len(actual['Servers']),
        'innerFieldsCompared':len(targets),'wholeIndependentJcaParity':True,'cipherAuthenticated':False,'apkCodeExecuted':False,
        'clearJsonSha256':hashlib.sha256(json.dumps(actual,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest(),'rawOutputBytes':len(codec.run(data).encode())}
    if worker:
        from cloud.workers.python.engine import decode_provider_catalog
        r=decode_provider_catalog('litron-pro-vpn',data)
        if r['structuredJson']!=reference or json.loads(r['rawText'])!=reference or r['isPartial'] is not False:raise ValueError('WHOLE_WORKER_JSON_MISMATCH')
        result['wholeWorkerParity']=True
    return result
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('catalog',type=Path);p.add_argument('--worker',action='store_true');p.add_argument('--report',type=Path);a=p.parse_args();r=verify(a.catalog,a.worker)
    if a.report:a.report.write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps(r))
