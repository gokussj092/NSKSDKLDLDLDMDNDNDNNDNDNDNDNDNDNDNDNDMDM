#!/usr/bin/env python3
"""Dump exact Dalvik methods to a private JSON file, without executing code."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dex",type=Path)
    parser.add_argument("class_name",help="Exact descriptor, e.g. Lcom/example/Config$1;")
    parser.add_argument("method")
    parser.add_argument("output",type=Path)
    args=parser.parse_args()
    if args.dex.stat().st_size>100*1024*1024:parser.error("DEX exceeds limit")
    from loguru import logger
    logger.remove()
    from androguard.core.dex import DEX
    data=args.dex.read_bytes();dex=DEX(data)
    matches=[]
    for cls in dex.get_classes():
        if cls.get_name()!=args.class_name:continue
        for method in cls.get_methods():
            if method.get_name()==args.method:
                matches.append({"descriptor":method.get_descriptor(),"instructions":[
                    {"opcode":i.get_name(),"operands":i.get_output()} for i in method.get_instructions()]})
    if not matches:parser.error("Exact class/method not found")
    report={"dexSha256":hashlib.sha256(data).hexdigest(),"class":args.class_name,"method":args.method,"matches":matches}
    args.output.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with os.fdopen(os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"w",encoding="utf-8") as f:
        json.dump(report,f,ensure_ascii=True,indent=2)
    print(json.dumps({"methods":len(matches),"instructions":sum(len(m["instructions"]) for m in matches)}))


if __name__=="__main__":main()
