#!/usr/bin/env python3
"""Run the HTTP Conexión refresh and affected regressions and affected Cloud regressions in their proper cwd."""
import argparse,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[5]
NODE_TESTS=['http-conexion-firebase','genis-vpn','speicers-turbo-vpn','http-conexion','namo-vpn','fnf-tunnel-bd','alsaher-vip','halcon-r-net','server-vpn-provider',
 'server-vpn-worker-contract','alfaisal-tunnel-plus','server-vpn-catalog','zig-tunnel',
 'mm-tunnel','text-format-catalog','vip-snipher-pro','server-vpn-any-speicers',
 'enaa-tunnel','ultra-tunnel','jyfast-vpn-ultra']
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private_output',type=Path);a=p.parse_args()
    a.private_output.mkdir(parents=True,exist_ok=True,mode=0o700);results=[]
    commands=[('python-http',[sys.executable,'-m','unittest','discover','-s','tests','-p','test_http_conexion*.py','-v'],ROOT),
      ('python-genis',[sys.executable,'-m','unittest','discover','-s','analysis/com.doriaxvip.tunnel/76/tests','-v'],ROOT),
      ('node',['node','--test',*['tests/'+t+'.test.mjs' for t in NODE_TESTS]],ROOT/'cloud/web')]
    for name,cmd,cwd in commands:
        done=subprocess.run(cmd,cwd=cwd,capture_output=True,text=True,timeout=120)
        log=a.private_output/(name+'.log');log.write_text(done.stdout+done.stderr);log.chmod(0o600)
        results.append({'runtime':name,'exit_code':done.returncode,'cwd':str(cwd.relative_to(ROOT)) or '.',
          'arguments':cmd[1:],'log':log.name})
        print(done.stdout+done.stderr)
    (a.private_output/'checks.json').write_text(json.dumps(results,indent=2)+'\n')
    if any(r['exit_code'] for r in results):raise SystemExit(1)
if __name__=='__main__':main()
