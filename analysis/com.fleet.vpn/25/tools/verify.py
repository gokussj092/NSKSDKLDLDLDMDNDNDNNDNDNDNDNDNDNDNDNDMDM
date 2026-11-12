#!/usr/bin/env python3
"""Whole real catalog parity: independent JCA, owner helper, Python and worker."""
import argparse,base64,copy,hashlib,importlib.util,json,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.Litron_VPN import codec
def oracle(jobs):
    with tempfile.TemporaryDirectory(prefix='litron-jca-') as folder:
        path=Path(folder)/'commands.tsv';path.write_text(''.join(op+'\t'+base64.b64encode(value.encode()).decode()+'\n' for op,value in jobs));path.chmod(0o600)
        r=subprocess.run(['java',str(Path(__file__).with_name('LitronOracle.java')),str(path)],capture_output=True,timeout=60)
    if r.returncode:raise ValueError('INDEPENDENT_JCA_FAILED')
    lines=r.stdout.decode().splitlines()
    if len(lines)!=len(jobs):raise ValueError('INDEPENDENT_RESULT_COUNT')
    return [base64.b64decode(x,validate=True).decode('utf-8') for x in lines]
def verify(path,worker):
    data=Path(path).read_bytes();outer=json.loads(oracle([('open',data.decode())])[0]);reference=copy.deepcopy(outer)
    targets=[];jobs=[]
    def collect(v):
        if isinstance(v,dict):
            for k,item in v.items():
                if isinstance(item,str) and item and all(0x2000<=ord(c)<=0x200f for c in item):targets.append((v,k));jobs.append(('hidden',item))
                else:collect(item)
        elif isinstance(v,list):
            for k,item in enumerate(v):
                if isinstance(item,str) and item and all(0x2000<=ord(c)<=0x200f for c in item):targets.append((v,k));jobs.append(('hidden',item))
                else:collect(item)
    collect(reference)
    for value,(parent,key) in zip(oracle(jobs) if jobs else [],targets):parent[key]=value
    actual=codec.decode_catalog(data)
    if actual!=reference:raise ValueError('WHOLE_JCA_JSON_MISMATCH')
    script=Path(__file__).with_name('provided_spdecode_litronvpn.py');s=importlib.util.spec_from_file_location('owner_litron_reference',script);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad,unpad
    owner=m._walk(m._decode_catalog(data,AES,pad,unpad,m._aes_key()),AES,unpad,m._aes_key())
    if owner!=reference:raise ValueError('WHOLE_OWNER_JSON_MISMATCH')
    result={'inputBytes':len(data),'inputSha256':hashlib.sha256(data).hexdigest(),'version':actual['Version'],
        'servers':len(actual['Servers']),'networks':len(actual['Networks']),'hiddenFieldsCompared':len(targets),
        'wholeIndependentJcaParity':True,'wholeProvidedHelperParity':True,'providedAutoInstallerCalled':False,
        'clearJsonSha256':hashlib.sha256(json.dumps(actual,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest(),
        'rawOutputBytes':len(codec.run(data).encode()),'apkCodeExecuted':False,'cipherAuthenticated':False}
    if worker:
        from cloud.workers.python.engine import decode_provider_catalog
        r=decode_provider_catalog('litron-vpn',data)
        if r['structuredJson']!=reference or json.loads(r['rawText'])!=reference or r['isPartial'] is not False:raise ValueError('WHOLE_WORKER_JSON_MISMATCH')
        result['wholeWorkerParity']=True
    return result
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('catalog',type=Path);p.add_argument('--worker',action='store_true');p.add_argument('--report',type=Path)
    a=p.parse_args();r=verify(a.catalog,a.worker)
    if a.report:a.report.write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps(r))
