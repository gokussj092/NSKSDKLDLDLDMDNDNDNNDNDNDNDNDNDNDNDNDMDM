#!/usr/bin/env python3
"""Real Firebase→download→JCA/CLI/isolated-worker whole-document comparison."""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[5]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from verify import reference
from decoders.Python.apps.HTTP_Conexion import firebase,codec,server_catalog_decoder as cli
from cloud.workers.python.engine import decode_provider_catalog


def private(path,data):
    path.write_bytes(data);path.chmod(0o600)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args();d=a.private
    calls=[]
    def transport(url,headers,body=None,method='POST'):
        role='cleanup' if method=='DELETE' else 'installations' if url.endswith('/installations') else 'remote_config'
        result=firebase.request(url,headers,body,method)
        calls.append({'role':role,'http_status':200});return result
    config=firebase.fetch_config(transport)
    private(d/'firebase-effective.json',json.dumps(config,ensure_ascii=False).encode())
    raw=cli.download_raw(config);private(d/'remote.enc',raw)
    bundle=codec.pack_catalog(raw,config['password']);private(d/'automatic.bundle',bundle)
    expected,count,unique=reference(raw,config['password'].encode(),codec.FIELD_KEY)
    actual=json.loads(codec.run(bundle));assert actual==expected
    command=[sys.executable,str(ROOT/'decoders/Python/apps/HTTP_Conexion/server_catalog_decoder.py'),str((d/'automatic.bundle').resolve())]
    done=subprocess.run(command,capture_output=True,check=True,timeout=45);assert json.loads(done.stdout)==expected
    worker=decode_provider_catalog('http-conexion',bundle)
    assert worker['structuredJson']==expected and json.loads(worker['rawText'])==expected and not worker['isPartial']
    private(d/'worker.json',(json.dumps(worker,ensure_ascii=False)+'\n').encode())
    private(d/'result.json',(codec.run(bundle)+'\n').encode())
    prior=d/'automatic.json';prior_equal=json.loads(prior.read_text())==expected if prior.exists() else None
    report={'requests':calls,'source_host':'raw.githubusercontent.com','source_sha256':hashlib.sha256(config['source'].encode()).hexdigest(),
      'password_sha256':hashlib.sha256(config['password'].encode()).hexdigest(),'remote_bytes':len(raw),
      'remote_sha256':hashlib.sha256(raw).hexdigest(),'bundle_bytes':len(bundle),'version':actual['Version'],
      'servers':len(actual['Servers']),'gcm_fields':count,'unique_gcm_fields':unique,
      'whole_jca_equal':True,'whole_cli_equal':True,'whole_worker_equal':True,'prior_real_auto_cli_equal':prior_equal,
      'cache_seconds':firebase.TTL_SECONDS,'cleanup_http':next((x['http_status'] for x in calls if x['role']=='cleanup'),None)}
    (d/'auto-verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))


if __name__=='__main__':main()
