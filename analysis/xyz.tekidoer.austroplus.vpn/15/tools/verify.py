#!/usr/bin/env python3
"""Whole-document proof against the preserved independent Java XXTEA/XOR oracle."""
import argparse,base64,copy,hashlib,json,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.AustroPlus_VPN import codec
SERVERS={'server_host','username','password','udp_host','udp_obf','udp_auth','dns_pubkey','name_server','dns_user','dns_pass',
    'v2uuid','v2_host','v2path','cf_server','cf_user','cf_pass','ws_host','ws_user','ws_pass','wireguard'}
TWEAKS={'proxy_host','custom_payload','custom_bug','custom_sni','custom_dns','custom_v2_sni','custom_v2ray'}
def oracle(jobs):
    with tempfile.TemporaryDirectory(prefix='austro-oracle-') as folder:
        path=Path(folder)/'commands.tsv'
        path.write_text(''.join(op+'\t'+base64.b64encode(data).decode()+'\n' for op,data in jobs));path.chmod(0o600)
        r=subprocess.run(['java',str(ROOT/'tests/golden/austroplus_oracle.java'),str(path)],capture_output=True,timeout=60)
    if r.returncode:raise ValueError('JAVA_ORACLE_FAILED')
    rows=r.stdout.decode().splitlines()
    if len(rows)!=len(jobs):raise ValueError('ORACLE_COUNT_MISMATCH')
    return [base64.b64decode(x,validate=True) for x in rows]
def verify(path,worker):
    data=Path(path).read_bytes()
    obj=json.loads(oracle([('xxd',base64.b64decode(b''.join(data.split()),validate=True))])[0]);independent=copy.deepcopy(obj)
    jobs=[];targets=[]
    if 'url_updater' in independent:jobs.append(('xor',independent['url_updater'].encode()));targets.append((independent,'url_updater'))
    for section,fields in [('Servers',SERVERS),('Tweaks',TWEAKS)]:
        for item in independent[section]:
            for key in sorted(fields&item.keys()):jobs.append(('xor',item[key].encode()));targets.append((item,key))
    rows=oracle(jobs)
    for row,(parent,key) in zip(rows,targets):parent[key]=row.decode('utf-8')
    actual=codec.decode_catalog(data)
    if actual!=independent:raise ValueError('WHOLE_JSON_MISMATCH')
    report={'inputBytes':len(data),'inputSha256':hashlib.sha256(data).hexdigest(),'version':actual['version'],
        'servers':len(actual['Servers']),'tweaks':len(actual['Tweaks']),'protectedFieldsCompared':len(targets),
        'wholeIndependentJavaParity':True,'clearJsonSha256':hashlib.sha256(json.dumps(actual,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest(),
        'rawOutputBytes':len(codec.render(actual).encode()),'apkCodeExecuted':False}
    if worker:
        from cloud.workers.python.engine import decode_provider_catalog
        r=decode_provider_catalog('austroplus-vpn',data)
        if r['structuredJson']!=independent or json.loads(r['rawText'])!=independent or r['isPartial'] is not False:raise ValueError('WHOLE_WORKER_MISMATCH')
        report['wholeWorkerParity']=True
    return report
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('catalog',type=Path);p.add_argument('--worker',action='store_true');p.add_argument('--report',type=Path)
    a=p.parse_args();r=verify(a.catalog,a.worker)
    if a.report:a.report.write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps(r))
