#!/usr/bin/env python3
"""Whole independent Node/Python/CLI/worker equality, no filtering or decryption."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.CATNET_VPN import server_catalog_decoder as cli
from cloud.workers.python.engine import decode_provider_catalog
def private_write(path,data):
    path.touch(mode=0o600,exist_ok=True);path.chmod(0o600);path.write_bytes(data)
def verify(path,out):
    data=path.read_bytes()
    ref=subprocess.run(['node',str(Path(__file__).with_name('JsonOracle.mjs')),str(path.resolve())],
        capture_output=True,check=True,timeout=30)
    expected=json.loads(ref.stdout);actual=json.loads(cli.run(data));assert actual==expected
    result=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/CATNET_VPN/server_catalog_decoder.py'),str(path.resolve())],
        capture_output=True,check=True,timeout=30);assert json.loads(result.stdout)==expected
    worker=decode_provider_catalog('catnet-vpn',data)
    assert worker['structuredJson']==expected and json.loads(worker['rawText'])==expected and worker['isPartial'] is False
    private_write(out/(path.stem+'.json'),json.dumps(actual,ensure_ascii=False,indent=2).encode())
    private_write(out/(path.stem+'.worker.json'),json.dumps(worker,ensure_ascii=False).encode())
    return {'input':path.name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
        'servers':len(actual['servers']),'keys':list(actual),'node_python_cli_worker_whole_equal':True,
        'canonical_json_sha256':hashlib.sha256(json.dumps(actual,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('catalog',type=Path);p.add_argument('private_output',type=Path)
    p.add_argument('--download',action='store_true');a=p.parse_args();a.private_output.mkdir(parents=True,exist_ok=True,mode=0o700)
    paths=[a.catalog]
    if a.download:
        path=a.private_output/'downloaded.json';private_write(path,cli.download());paths.append(path)
    report=[verify(path,a.private_output) for path in paths]
    (a.private_output/'summary.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':main()
