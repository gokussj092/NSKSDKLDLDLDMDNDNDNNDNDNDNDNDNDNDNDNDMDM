#!/usr/bin/env python3
"""Capture distinct live-egress and real-byte simulated-HTTP outcomes."""
import argparse,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args();d=a.private.resolve()
    script=str(Path(__file__).with_name('probe_node.mjs'));rows=[]
    for args in [['--real'],['--replay',str(d/'remote.bin'),str(d/'worker.json')]]:
        r=subprocess.run(['node',script,*args],cwd=ROOT,text=True,capture_output=True,timeout=30)
        if r.returncode not in (0,3):raise ValueError('Unexpected Node probe failure')
        value=json.loads(r.stdout);value['exit_code']=r.returncode;rows.append(value)
    (d/'node-transport.json').write_text(json.dumps(rows,indent=2)+'\n');print(json.dumps(rows))
if __name__=='__main__':main()
