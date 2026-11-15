#!/usr/bin/env python3
"""Run only scoped Cloud/Python tests; save sanitized counts and private logs."""
import argparse,json,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
TESTS=['xxpicore-tunnel','server-vpn-catalog','c12-provider-controls','catnet-vpn','fnf-tunnel-bd','jyfast-vpn-ultra','genis-vpn','http-conexion','mm-tunnel','alsaher-vip','enaa-tunnel','namo-vpn','ultra-tunnel','vip-snipher-pro','zig-tunnel','text-format-catalog','halcon-r-net','alfaisal-tunnel-plus','speicers-turbo-vpn','server-vpn-any-speicers']
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args();d=a.private;d.mkdir(parents=True,exist_ok=True)
    commands=[('python',[sys.executable,'-m','unittest','discover','-s','analysis/pro.xxpicore.tunnel/118/tests','-v'],ROOT),
      ('node',['node','--test','--test-reporter=tap',*['tests/'+name+'.test.mjs' for name in TESTS]],ROOT/'cloud/web')]
    report={}
    for name,cmd,cwd in commands:
        r=subprocess.run(cmd,cwd=cwd,text=True,capture_output=True,timeout=60);log=r.stdout+r.stderr
        f=d/(name+'-tests.log');f.touch(mode=0o600,exist_ok=True);f.chmod(0o600);f.write_text(log)
        if r.returncode:raise ValueError(name+' tests failed; inspect private log')
        pattern=r'Ran (\d+) tests' if name=='python' else r'# tests (\d+)'
        m=re.search(pattern,log);assert m
        report[name]={'passed':int(m[1]),'failed':0,'files':1 if name=='python' else len(TESTS),'synthetic':True}
    (d/'checks.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':main()
