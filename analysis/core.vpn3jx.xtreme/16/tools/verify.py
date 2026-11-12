#!/usr/bin/env python3
"""Compare the entire Wolf16 JSON against independent Go Argon2id/JCA-compatible GCM."""
import argparse,base64,copy,hashlib,json,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.Wolf_Custom_VPN import codec,codec_v16
from native_recipe import inspect,pointer
from native_inspect import Go32Image
def oracle(binary,jobs):
    stream="\n".join(json.dumps(j) for j in jobs)+"\n"
    p=subprocess.run([str(binary)],input=stream,text=True,capture_output=True,timeout=180)
    if p.returncode:raise ValueError("INDEPENDENT_ORACLE_FAILED")
    rows=[json.loads(s) for s in p.stdout.splitlines()]
    if len(rows)!=len(jobs):raise ValueError("INCOMPLETE_ORACLE_RESULT")
    return rows
def job(seed,value,transport=False):
    return {"Operation":"open","Seed":base64.b64encode(seed).decode(),"Value":value,"Transport":transport}
def verify(path,elf,binary,worker=False):
    image=Go32Image(elf);seed_a,recipe=inspect(elf)
    seed_b=image.read(pointer(image,0xfd3bf8,0xfd3bfc),32)
    if seed_a!=codec_v16.CATALOG_SEED or seed_b!=codec_v16.FIELD_SEED:raise ValueError("NATIVE_BINDING_MISMATCH")
    data=Path(path).read_bytes()
    if not 0<len(data)<=codec.MAX_BYTES:raise ValueError("CATALOG_BOUNDS")
    text=data.decode("utf-8-sig").strip();transport=len(text)%4==1
    row=oracle(binary,[job(seed_a if transport else seed_b,text,transport)])[0]
    if not row["OK"]:raise ValueError("OUTER_NOT_AUTHENTICATED")
    obj=json.loads(base64.b64decode(row["Value"],validate=True))
    independent=copy.deepcopy(obj);jobs=[];targets=[]
    def walk(value):
        if isinstance(value,dict):
            for key,item in value.items():
                if isinstance(item,str) and len(item)>=60:
                    try:packed=base64.b64decode(item.replace("\r","").replace("\n",""),validate=True)
                    except ValueError:continue
                    if len(packed)>=44:jobs.append(job(seed_b,item));targets.append((value,key))
                else:walk(item)
        elif isinstance(value,list):
            for item in value:walk(item)
    walk(independent);rows=oracle(binary,jobs) if jobs else []
    encrypted=0
    for row,(parent,key) in zip(rows,targets):
        if row["OK"]:parent[key]=base64.b64decode(row["Value"],validate=True).decode();encrypted+=1
    started=time.monotonic();actual=codec.decode_catalog(data);seconds=time.monotonic()-started
    if actual!=independent:raise ValueError("WHOLE_JSON_MISMATCH")
    report={"inputBytes":len(data),"inputSha256":hashlib.sha256(data).hexdigest(),
        "version":actual["Version"],"servers":len(actual["Servers"]),"networks":len(actual["Networks"]),
        "encryptedFieldsCompared":encrypted,"wholeIndependentGoParity":True,"decoderSeconds":round(seconds,3),
        "clearJsonSha256":hashlib.sha256(json.dumps(actual,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest(),
        "rawOutputBytes":len(codec.render(actual).encode()),"apkCodeExecuted":False}
    if worker:
        from cloud.workers.python.engine import decode_provider_catalog
        start=time.monotonic();r=decode_provider_catalog("wolf-custom-vpn",data)
        if r["structuredJson"]!=independent or json.loads(r["rawText"])!=independent or r["isPartial"] is not False:
            raise ValueError("WHOLE_WORKER_MISMATCH")
        report["wholeWorkerParity"]=True;report["workerSeconds"]=round(time.monotonic()-start,3)
    return report
def main():
    p=argparse.ArgumentParser();p.add_argument("catalog",type=Path);p.add_argument("--elf",type=Path,required=True)
    p.add_argument("--oracle",type=Path,required=True);p.add_argument("--worker",action="store_true");p.add_argument("--report",type=Path)
    a=p.parse_args();r=verify(a.catalog,a.elf,a.oracle,a.worker)
    if a.report:a.report.write_text(json.dumps(r,indent=2)+"\n")
    print(json.dumps(r))
if __name__=="__main__":main()

