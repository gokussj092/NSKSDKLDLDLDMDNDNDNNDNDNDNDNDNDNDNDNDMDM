"""Inspect static format labels from the original local string accessor."""
import argparse,json
from pathlib import Path
from probe_kdf import load

def main():
    p=argparse.ArgumentParser();p.add_argument('library');p.add_argument('output',type=Path);a=p.parse_args()
    e=load(a.library);strings={}
    for i in range(1500):
        try:
            result=e.call(0xdcbd48,e.env,0,i,limit=1_000_000)
            value=e.objects.get(result)
            if not isinstance(value,str):break
            strings[i]=value
        except Exception as error:print('stopped',i,type(error).__name__,str(error));break
    a.output.write_text(json.dumps(strings,indent=2))
    print('count',len(strings))
    # Static names/format labels only; URLs and arbitrary values stay private.
    print({i:s for i,s in strings.items() if any(x in s for x in ('NATIVE','HCCFG','app-config','HCX','HPC','n15','n16','n17','n18'))})

if __name__=='__main__':main()
