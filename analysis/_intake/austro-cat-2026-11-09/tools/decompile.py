#!/usr/bin/env python3
"""Run the unchanged pinned full JADX installer with a recorded static recipe."""
import argparse,hashlib,importlib.util,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
def inspect(folder):
    folder=Path(folder).resolve();identity=json.loads((folder/'identity.json').read_text())
    apk=folder/'base.apk'
    if hashlib.sha256(apk.read_bytes()).hexdigest()!=identity['apkSha256']:raise ValueError('APK_MISMATCH')
    path=ROOT/'scripts/apk_analysis/decompile.py';spec=importlib.util.spec_from_file_location('pinned_jadx',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);jar=module.install()
    with (folder/'jadx.log').open('wb') as log:
        rc=subprocess.run(['java','-Xmx2200m','-XX:ActiveProcessorCount=3','-cp',str(jar),'jadx.cli.JadxCLI',
            '--no-res','--decompilation-mode','auto','-j','3','-d',str(folder/'jadx'),str(apk)],
            stdout=log,stderr=subprocess.STDOUT,timeout=420).returncode
    result={'package':identity['package'],'build':identity['versionCode'],'jadxVersion':module.VERSION,
        'jadxJarSha256':module.JAR_SHA256,'jadxExitCode':rc,'apkCodeExecuted':False}
    (folder/'static-proof.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();inspect(a.private)
