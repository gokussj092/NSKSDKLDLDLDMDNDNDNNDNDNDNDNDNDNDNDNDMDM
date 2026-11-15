#!/usr/bin/env python3
"""CATNET plus NAMO Python regressions and affected Cloud tests; no Android build."""
import argparse,json,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
NODE_TESTS=['catnet-vpn','namo-vpn','http-conexion','http-conexion-firebase','genis-vpn','speicers-turbo-vpn',
 'fnf-tunnel-bd','alsaher-vip','halcon-r-net','server-vpn-provider','server-vpn-worker-contract',
 'alfaisal-tunnel-plus','server-vpn-catalog','zig-tunnel','mm-tunnel','text-format-catalog',
 'vip-snipher-pro','server-vpn-any-speicers','enaa-tunnel','ultra-tunnel','jyfast-vpn-ultra']
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private_output',type=Path);a=p.parse_args()
    a.private_output.mkdir(parents=True,exist_ok=True,mode=0o700);results=[]
    commands=[('python',[sys.executable,'-m','unittest','discover','-s','tests','-p','test_catnet_vpn.py','-v'],ROOT),
        ('namo',[sys.executable,'-m','unittest','discover','-s','analysis/com.appxrayservice.namovpn/35/tests','-v'],ROOT),
        ('node',['node','--test',*['tests/'+n+'.test.mjs' for n in NODE_TESTS]],ROOT/'cloud/web')]
    for name,cmd,cwd in commands:
        done=subprocess.run(cmd,cwd=cwd,capture_output=True,text=True,timeout=120);log=done.stdout+done.stderr
        f=a.private_output/(name+'.log');f.touch(mode=0o600,exist_ok=True);f.chmod(0o600);f.write_text(log)
        pattern=r'tests (\d+)' if name=='node' else r'Ran (\d+) tests'
        match=re.search(pattern,log);count=int(match[1]) if match else None
        results.append({'runtime':name,'exit_code':done.returncode,'tests':count,'cwd':str(cwd.relative_to(ROOT)) or '.',
            'arguments':cmd[1:],'log':f.name});print(json.dumps(results[-1]))
    (a.private_output/'checks.json').write_text(json.dumps(results,indent=2)+'\n')
    if any(r['exit_code'] for r in results):raise SystemExit(1)
if __name__=='__main__':main()
