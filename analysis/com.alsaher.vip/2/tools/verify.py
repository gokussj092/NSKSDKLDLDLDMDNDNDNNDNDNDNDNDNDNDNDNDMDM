#!/usr/bin/env python3
"""Whole-document Java/CLI/isolated-worker comparison, real or synthetic inputs.

No real profiles are printed. --download makes the original public updater GET.
"""
import argparse,base64,hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))

def oracle(mode,values):
    data=''.join(mode+'\t'+base64.b64encode(v.encode()).decode()+'\n' for v in values)
    result=subprocess.run(['java',str(ROOT/'tests/golden/zig_oracle.java')],input=data,
      text=True,capture_output=True,check=True,timeout=45)
    out=[base64.b64decode(v).decode('utf-8') for v in result.stdout.splitlines()]
    if len(out)!=len(values):raise ValueError('Incomplete Java reference')
    return out

def reference(data):
    doc=json.loads(oracle('D',[data.decode().strip()])[0]);entries=[]
    def fields(row,names):
        for k in names:
            if row.get(k) not in (None,''):entries.append((row,k,row[k]))
    fields(doc,('config_url','account_api','upload_get_api','upload_post_api',
                'cloud_get_api','cloud_post_api','AppConfPass','Ovpn_Cert'))
    for row in doc['Servers']:
        fields(row,('ServerIP','ServerCloudFront','ServerHTTP','ProxyHost','Username','Password','ovpnCertificate'))
    for name in ('HTTPNetworks','DirectNetworks','DNSNetworks','UDPNetworks','SSLNetworks'):
        for row in doc.get(name,[]):
            fields(row,('NetworkPayload','NetworkFrontQuery','NetworkBackQuery','SquidProxy','SSLSNI','SSLPayload'))
    unique=list(dict.fromkeys(v for _,_,v in entries));mapping=dict(zip(unique,oracle('D',unique)))
    for row,k,v in entries:row[k]=mapping[v]
    return doc,len(entries),len(unique)

def verify(path,private_output,runtime=True):
    from decoders.Python.apps.ALSAHER_VIP import server_catalog_decoder as catalog
    data=path.read_bytes();expected,fields,unique=reference(data)
    actual=json.loads(catalog.run(data))
    if actual!=expected:raise ValueError('Whole JSON differs from Java')
    out=private_output/(path.stem+'.json');out.touch(mode=0o600,exist_ok=True);out.chmod(0o600)
    out.write_text(json.dumps(actual,ensure_ascii=False,indent=2)+'\n')
    result={'source':path.name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
      'version':actual['Version'],'counts':{k:len(v) for k,v in actual.items() if isinstance(v,list)},
      'encrypted_fields':fields,'unique_encrypted_fields':unique,'whole_java_equal':True,
      'whole_cli_equal':True,'whole_worker_equal':None}
    done=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/ALSAHER_VIP/server_catalog_decoder.py'),str(path.resolve())],
      capture_output=True,check=True,timeout=30)
    if json.loads(done.stdout)!=expected:raise ValueError('CLI mismatch')
    if runtime:
        from cloud.workers.python.engine import decode_provider_catalog
        worker=decode_provider_catalog('alsaher-vip',data)
        if worker['structuredJson']!=expected or json.loads(worker['rawText'])!=expected or worker['isPartial']:
            raise ValueError('Worker mismatch')
        result['whole_worker_equal']=True
        f=private_output/(path.stem+'.worker.json');f.touch(mode=0o600,exist_ok=True);f.chmod(0o600)
        f.write_text(json.dumps(worker,ensure_ascii=False))
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('catalog',type=Path)
    p.add_argument('private_output',type=Path);p.add_argument('--download',action='store_true')
    p.add_argument('--no-worker',action='store_true');a=p.parse_args()
    a.private_output.mkdir(parents=True,exist_ok=True,mode=0o700)
    reports=[verify(a.catalog,a.private_output,not a.no_worker)]
    if a.download:
        from decoders.Python.apps.ALSAHER_VIP.server_catalog_decoder import download
        data=download();f=a.private_output/'downloaded.enc';f.touch(mode=0o600,exist_ok=True);f.chmod(0o600);f.write_bytes(data)
        reports.append(verify(f,a.private_output,not a.no_worker))
    (a.private_output/'summary.json').write_text(json.dumps(reports,indent=2)+'\n')
    print(json.dumps(reports))
if __name__=='__main__':main()
