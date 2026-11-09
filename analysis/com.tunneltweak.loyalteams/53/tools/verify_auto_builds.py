#!/usr/bin/env python3
"""Real version-only recovery from the previously rejected build51, then full JCA proof."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.Tunneltweak import network,build_history as history
def main():
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();folder=a.private.resolve()
    folder.mkdir(parents=True,exist_ok=True,mode=0o700);folder.chmod(0o700)
    state=folder/'builds.json'
    if not state.exists():
        s=history.seed();s['auto']['build']=51;state.write_text(json.dumps(s,indent=2)+'\n');state.chmod(0o600)
    data=network.download(state_path=state);cipher=folder/'catalog.bin'
    cipher.write_bytes(data);cipher.chmod(0o600)
    proof=folder/'proof.json';r=subprocess.run([sys.executable,str(Path(__file__).with_name('verify.py')),str(cipher),
        '--worker','--report',str(proof)],capture_output=True,text=True,timeout=60)
    if r.returncode:raise ValueError('WHOLE_JCA_WORKER_PROOF_FAILED')
    s=history.load(state)
    if s['auto']['build']<53 or not next(x for x in s['builds'] if x['build']==s['auto']['build'])['working']:
        raise ValueError('BUILD_RECOVERY_NOT_CONFIRMED')
    report={'scope':'REAL_HTTP426_RECOVERY_AND_COMPLETE_CATALOG_PROOF','initialBuild':51,
        'selectedBuild':s['auto']['build'],'historyPersisted':True,'noCatalogOrCredentialsInHistory':True,
        'catalogProof':json.loads(proof.read_text()),'apkCodeExecuted':False}
    (folder/'auto-proof.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':main()
