"""Compare complete authorized ALFAISAL catalogs with independent JCA; metrics only."""
from __future__ import annotations
import argparse,base64,hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from decoders.Python.apps.ALFAISAL_Tunnel_Plus import codec


def oracle(cases):
    lines=''.join(str(mode)+'\t'+base64.b64encode(value).decode()+'\n' for mode,value in cases)
    result=subprocess.run(['java',str(ROOT/'tests/golden/alfaisal_oracle.java')],input=lines,text=True,capture_output=True,check=True,timeout=45)
    values=[base64.b64decode(x,validate=True) for x in result.stdout.splitlines()]
    if len(values)!=len(cases):raise ValueError('Incomplete JCA result')
    return values


def entries(doc):
    # Independent field consumers from build39, without importing codec schemas.
    result=[]
    def add(obj,names):
        for key in names:
            if obj.get(key) not in (None,''):result.append((obj,key))
    add(doc,('Username','Password'))
    for row in doc['Servers']:add(row,('Username','Password','SSHUsername','SSHPassword'))
    for section in ('Networks','SSLNetworks'):
        for row in doc[section]:
            add(row,('Payload','SNIHost'))
            if isinstance(row.get('ProxySettings'),dict):add(row['ProxySettings'],('Squid',))
    return result


def verify(path,runtime=False):
    data=path.read_bytes();expected=json.loads(oracle([(0,data)])[0]);fields=entries(expected)
    unique=list(dict.fromkeys(row[key] for row,key in fields))
    reference=dict(zip(unique,oracle([(2,value.encode()) for value in unique])))
    passthrough=sum(reference[row[key]]==row[key].encode() for row,key in fields)
    for row,key in fields:row[key]=reference[row[key]].decode('utf-8')
    actual=codec.decode_catalog(data)
    if actual!=expected:raise ValueError('Complete document differs from JCA')
    report={'source':path.name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
        'version':actual['Version'],**{k:len(actual[k]) for k in ('Servers','Networks','SSLNetworks')},
        'nonemptyFields':len(fields),'uniqueFields':len(unique),'cbcFallbackFields':passthrough,'completeJcaEqual':True}
    if runtime:
        from cloud.workers.python.engine import decode_provider_catalog
        worker=decode_provider_catalog('alfaisal-tunnel-plus',data)
        if worker['structuredJson']!=expected or json.loads(worker['rawText'])!=expected:raise ValueError('Worker differs')
        cli=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/ALFAISAL_Tunnel_Plus/server_catalog_decoder.py'),'--stdin'],input=data,capture_output=True,check=True,timeout=30,cwd='/tmp')
        if json.loads(cli.stdout)!=expected or cli.stderr:raise ValueError('CLI differs')
        report['workerAndCliEqual']=True
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('files',type=Path,nargs='+');p.add_argument('--runtime',action='store_true');a=p.parse_args()
    for file in a.files:print(json.dumps(verify(file,a.runtime),sort_keys=True))
