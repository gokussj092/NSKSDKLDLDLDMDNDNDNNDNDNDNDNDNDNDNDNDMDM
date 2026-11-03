#!/usr/bin/env python3
"""Compare the entire FNF catalog against independent JDK, CLI and child worker."""
import argparse,base64,hashlib,json,re,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from scripts.apk_analysis.bd_net_verify import java_batch
from decoders.Python.apps.FNF_TUNNEL_BD import server_catalog_decoder as catalog

def reference(data):
    with tempfile.TemporaryDirectory(prefix='fnf-jdk-') as tmp:
        helper=(ROOT/'tests/golden/apna_oracle.java').read_text()
        helper=re.sub(r'^import[^\n]+;\n','',helper,flags=re.MULTILINE)
        (Path(tmp)/'bd_net_oracle.java').write_text((ROOT/'tests/golden/bd_net_oracle.java').read_text()+'\n'+helper)
        text,binary=java_batch(tmp,['C\t'+base64.b64encode(data).decode()])[0]
        assert binary is None
        return json.loads(text)

def verify(path,out):
    data=path.read_bytes();expected=reference(data);actual=json.loads(catalog.run(data))
    assert actual==expected,'Whole Java document mismatch'
    done=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/FNF_TUNNEL_BD/server_catalog_decoder.py'),str(path.resolve())],
      capture_output=True,check=True,timeout=30)
    assert json.loads(done.stdout)==expected,'Whole CLI mismatch'
    from cloud.workers.python.engine import decode_provider_catalog
    worker=decode_provider_catalog('fnf-tunnel-bd',data)
    assert worker['structuredJson']==expected and json.loads(worker['rawText'])==expected and not worker['isPartial']
    for suffix,value in [('.json',actual),('.worker.json',worker)]:
        f=out/(path.stem+suffix);f.touch(mode=0o600,exist_ok=True);f.chmod(0o600)
        f.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
    return {'source':path.name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
      'version':actual['Version'],'counts':{k:len(v) for k,v in actual.items() if isinstance(v,list)},
      'whole_java_equal':True,'whole_cli_equal':True,'whole_worker_equal':True,
      'inner_decryption':'none; preserve original plaintext fields'}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private_output',type=Path)
    p.add_argument('catalogs',nargs='+',type=Path);p.add_argument('--download',action='store_true');a=p.parse_args()
    a.private_output.mkdir(parents=True,exist_ok=True,mode=0o700);paths=a.catalogs
    if a.download:
        f=a.private_output/'downloaded.enc';f.touch(mode=0o600,exist_ok=True);f.chmod(0o600);f.write_bytes(catalog.download());paths.append(f)
    results=[verify(f,a.private_output) for f in paths]
    (a.private_output/'summary.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(results))
if __name__=='__main__':main()
