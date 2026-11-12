#!/usr/bin/env python3
"""Exercise real CLI download and isolated Cloud worker; emit only safe counts."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from cloud.workers.python.engine import decode_provider_catalog
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args();d=a.private
    expected=json.loads((d/'decoded.json').read_text());raw=(d/'remote.bin').read_bytes()
    worker=decode_provider_catalog('xxpicore-tunnel',raw);assert worker['structuredJson']==expected and worker['isPartial'] is False
    f=d/'worker.json';f.touch(mode=0o600,exist_ok=True);f.chmod(0o600);f.write_text(json.dumps(worker,ensure_ascii=False))
    r=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/XXPICore_Tunnel/server_catalog_decoder.py'),'--download'],capture_output=True,timeout=60)
    assert r.returncode==0 and json.loads(r.stdout)==expected
    report={'status':'VERIFIED_REAL','wholeWorkerEqual':True,'wholeCliDownloadEqual':True,'cliBytes':len(r.stdout),'cliSha256':hashlib.sha256(r.stdout).hexdigest(),
      'version':expected['Version'],'servers':len(expected['Servers']),'networks':len(expected['Networks'])}
    (d/'cloud-verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':main()
