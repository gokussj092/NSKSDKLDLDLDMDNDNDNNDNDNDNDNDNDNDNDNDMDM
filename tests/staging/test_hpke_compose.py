#!/usr/bin/env python3
"""Exercise real operator HPKE guards against recreated Docker containers.

Synthetic keys only, isolated Compose project, no published ports/production
services. This is not a full VPS/Android E2E or a backup-restoration drill.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
source=(ROOT/'cloud/infra/vps/spdecodectl').read_text()
functions=source[source.index('hpke_runtime_ids(){'):source.index('\nupdate(){')]

def run(args,**kw):
    return subprocess.run(args,check=True,capture_output=True,text=True,timeout=180,**kw)

def main():
    with tempfile.TemporaryDirectory() as d:
        d=Path(d);config=d/'compose.json';envfile=d/'cloud.env'
        project='spdecode-rasp-stage-'+str(os.getpid())
        compose=['docker','--host=unix:///var/run/docker.sock','compose','-p',project,'-f',str(config)]
        # Obtain synthetic keys directly into local memory; never write to stdout.
        js='''const c=require('node:crypto'),k=c.generateKeyPairSync('x25519');process.stdout.write(JSON.stringify([{publicKey:k.publicKey.export({format:'jwk'}).x,privateKey:k.privateKey.export({format:'jwk'}).d}]));'''
        keyring=run(['node','-e',js]).stdout
        other=run(['node','-e',js]).stdout
        def deploy(key,enabled='true'):
            config.write_text(json.dumps({'services':{'web':{'image':'spdecode-rasp-stage:test',
                'environment':{'CLOUD_V2_HPKE_ENABLED':enabled,'CLOUD_V2_HPKE_KEYRING':key},
                'read_only':True,'cap_drop':['ALL'],'security_opt':['no-new-privileges:true']}}}))
            config.chmod(0o600)
            run(compose+['up','-d','--force-recreate'])
        envfile.write_text('CLOUD_V2_HPKE_ENABLED=true\nCLOUD_V2_HPKE_KEYRING=synthetic-present\n');envfile.chmod(0o600)
        # Run the actual guard functions, replacing only the environment-specific
        # Compose command and logging. No simulated hpke_runtime_ids function.
        def guard(command):
            import shlex
            shell='set -euo pipefail\nENVFILE='+shlex.quote(str(envfile))+'\n'
            shell+='compose(){ '+shlex.join(compose)+' "$@"; }\n'
            shell+='die(){ exit 41; }; log(){ :; };\n'+functions+'\n'+command
            return subprocess.run(['bash','-c',shell],capture_output=True,text=True,timeout=60)
        try:
            deploy(keyring)
            before=guard('hpke_expected_before_update');assert before.returncode==0,before.stderr
            kid=before.stdout.strip();assert len(kid)==16
            deploy(keyring)
            assert guard(f'hpke_confirm_after_update {kid}').returncode==0
            deploy('', 'true')
            assert guard(f'hpke_confirm_after_update {kid}').returncode!=0
            deploy(other)
            assert guard(f'hpke_confirm_after_update {kid}').returncode!=0
            deploy(keyring,'false')
            assert guard(f'hpke_confirm_after_update {kid}').returncode!=0
            deploy(keyring)
            assert guard(f'hpke_confirm_after_update {kid}').returncode==0
            print('PASS Compose: preserved key, missing key rejection, changed KID rejection, downgrade rejection, restore')
        finally:
            subprocess.run(compose+['down','--volumes','--remove-orphans'],capture_output=True,timeout=60)
if __name__=='__main__':main()
