#!/usr/bin/env python3
"""Dump selected DEX methods offline where JADX omitted Kotlin synthetic classes."""
import argparse,json
from pathlib import Path
from androguard.core.dex import DEX
from loguru import logger

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('dex',type=Path);p.add_argument('private_output',type=Path)
    p.add_argument('--class-prefix',default='Lnet/xj/vpn/api/ApiClient');a=p.parse_args()
    logger.remove();dex=DEX(a.dex.read_bytes());result=[]
    for cls in dex.get_classes():
        if not cls.get_name().startswith(a.class_prefix):continue
        for method in cls.get_methods():
            code=method.get_code()
            if code is None:continue
            result.append({'class':cls.get_name(),'name':method.get_name(),'descriptor':method.get_descriptor(),
                'instructions':[{'offset':off,'op':i.get_name(),'output':i.get_output()} for off,i in method.get_instructions_idx()]})
    a.private_output.touch(mode=0o600,exist_ok=True);a.private_output.chmod(0o600)
    a.private_output.write_text(json.dumps(result,indent=2));print(json.dumps({'methods':len(result)}))
if __name__=='__main__':main()
