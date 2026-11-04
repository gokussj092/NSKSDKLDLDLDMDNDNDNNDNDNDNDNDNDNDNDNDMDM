#!/usr/bin/env python3
"""Full Java/CLI/isolated-worker equality on saved or freshly downloaded NAMO."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from recover import oracle,LIB_SHA
from scripts.apk_analysis.elf_inspect import ElfImage
from decoders.Python.apps.NAMO_VPN import codec,server_catalog_decoder as catalog
def verify(path,key,out):
    data=path.read_bytes();expected=json.loads(oracle('D',key,[data])[0]);actual=json.loads(catalog.run(data))
    assert actual==expected,'Whole Python/Java mismatch'
    done=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/NAMO_VPN/server_catalog_decoder.py'),str(path.resolve())],
      capture_output=True,check=True,timeout=30)
    assert json.loads(done.stdout)==expected,'Whole CLI mismatch'
    from cloud.workers.python.engine import decode_provider_catalog
    worker=decode_provider_catalog('namo-vpn',data)
    assert worker['structuredJson']==expected and json.loads(worker['rawText'])==expected and not worker['isPartial']
    for suffix,value in [('.json',actual),('.worker.json',worker)]:
        f=out/(path.stem+suffix);f.touch(mode=0o600,exist_ok=True);f.chmod(0o600);f.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
    return {'source':path.name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
      'version':actual['Version'],'counts':{k:len(v) for k,v in actual.items() if isinstance(v,list)},
      'whole_java_equal':True,'whole_cli_equal':True,'whole_worker_equal':True}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('native',type=Path);p.add_argument('private_output',type=Path)
    p.add_argument('catalogs',nargs='+',type=Path);p.add_argument('--download',action='store_true');a=p.parse_args()
    assert hashlib.sha256(a.native.read_bytes()).hexdigest()==LIB_SHA
    key=ElfImage(a.native).cstring(0x541).encode();assert codec.FORMAT_KEY==key
    a.private_output.mkdir(parents=True,exist_ok=True,mode=0o700);paths=a.catalogs
    if a.download:
        f=a.private_output/'downloaded.enc';f.touch(mode=0o600,exist_ok=True);f.chmod(0o600);f.write_bytes(catalog.download());paths.append(f)
    results=[verify(path,key,a.private_output) for path in paths]
    (a.private_output/'summary.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(results))
if __name__=='__main__':main()
