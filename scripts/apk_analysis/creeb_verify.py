#!/usr/bin/env python3
"""Compare CREEB files with JDK DES/Properties and isolated worker; counts only."""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from decoders.Python.apps.CREEB_INJECTOR import codec


def reference(data):
    p=subprocess.run(["java","-XX:-UsePerfData",str(ROOT/"tests/golden/creeb_oracle.java")],
                     input=base64.b64encode(data).decode()+"\n",text=True,capture_output=True,check=True,timeout=60)
    return json.loads(p.stdout)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("files",nargs="*",type=Path)
    p.add_argument("--worker",action="store_true");a=p.parse_args()
    fixture=json.loads((ROOT/"tests/golden/creeb_vectors.json").read_text())
    values=[base64.b64decode(v["cipherBase64"]) for v in fixture["desFiles"]]
    values.extend(json.dumps(v,ensure_ascii=False).encode() for v in fixture["jsonBundles"])
    values.extend(path.read_bytes() for path in a.files)
    report={"documentsEqual":0,"desJdkEqual":0,"jsonBundles":0,"workerEqual":0,"realSamples":len(a.files)}
    for data in values:
        actual=codec.decode(data)
        if actual.get("type")==codec.BUNDLE_TYPE:
            assert actual==json.loads(data);report["jsonBundles"]+=1
        else:
            ref=reference(data)
            assert actual["raw_xml"].encode()==base64.b64decode(ref["xmlBase64"])
            assert actual["properties"]==ref["properties"]
            report["desJdkEqual"]+=1
        if a.worker:
            from cloud.workers.python.engine import decode_file
            result=decode_file("creeb",data)
            assert result["structuredJson"]==actual==json.loads(result["rawText"])
            assert result["isPartial"] is False
            report["workerEqual"]+=1
        report["documentsEqual"]+=1
    print(json.dumps(report))


if __name__=="__main__":main()
