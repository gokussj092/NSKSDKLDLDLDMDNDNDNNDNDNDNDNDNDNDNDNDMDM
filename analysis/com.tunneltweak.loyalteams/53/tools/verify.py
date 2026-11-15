#!/usr/bin/env python3
"""Full live Tunneltweak53 JSON parity using the existing independent JCA oracle."""
import argparse,base64,hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.Tunneltweak import codec
def verify(path,worker=False):
    data=Path(path).read_bytes()
    if not 0<len(data)<=codec.MAX_BYTES:raise ValueError("CATALOG_BOUNDS")
    outer=json.loads(data);blob=outer["data"]
    line="catalog\t"+base64.b64encode(blob.encode()).decode()+"\n"
    p=subprocess.run(["java",str(ROOT/"tests/golden/tunneltweak_oracle.java")],
        input=line,text=True,capture_output=True,timeout=60)
    if p.returncode:raise ValueError("INDEPENDENT_JCA_FAILED")
    expected=dict(outer,data=json.loads(base64.b64decode(p.stdout,validate=False)))
    actual=codec.decode_catalog(data)
    if actual!=expected:raise ValueError("WHOLE_JSON_MISMATCH")
    report={"inputBytes":len(data),"inputSha256":hashlib.sha256(data).hexdigest(),
        "servers":len(actual["data"]["servers"]),"configs":len(actual["data"]["configs"]),
        "wholeIndependentJcaParity":True,"clearJsonSha256":hashlib.sha256(json.dumps(actual,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest(),
        "rawOutputBytes":len(codec.render(actual).encode()),"apkCodeExecuted":False}
    if worker:
        from cloud.workers.python.engine import decode_provider_catalog
        r=decode_provider_catalog("tunneltweak",data)
        if r["structuredJson"]!=expected or json.loads(r["rawText"])!=expected or r["isPartial"] is not False:
            raise ValueError("WHOLE_WORKER_MISMATCH")
        report["wholeWorkerParity"]=True
    return report
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("catalog",type=Path);p.add_argument("--worker",action="store_true");p.add_argument("--report",type=Path)
    a=p.parse_args();r=verify(a.catalog,a.worker)
    if a.report:a.report.write_text(json.dumps(r,indent=2)+"\n")
    print(json.dumps(r))

