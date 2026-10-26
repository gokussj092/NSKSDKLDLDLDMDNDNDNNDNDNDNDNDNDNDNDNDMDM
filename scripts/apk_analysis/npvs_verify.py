#!/usr/bin/env python3
"""Private complete NPVS parity: independent JDK framing/crypto and Python layout.

Credentials are read only from stdin. Real values are neither printed nor saved.
The old app-key whitebox block is supplied to JDK from the already native-verified
table evaluator; PBKDF2, all AEADs, signature and inventory use JDK independently.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from decoders.Python import npvs


def jdk(cases, identity=None):
    lines=[]
    for raw,password in cases:
        hlen=int.from_bytes(raw[5:9],"big");h=raw[9:9+hlen]
        if h[50]==2:
            p=53+125*int.from_bytes(h[51:53],"big")
            wb=npvs._whitebox_block(h[p+2:p+18])
        elif raw[4]==6:
            p=53+125*int.from_bytes(h[51:53],"big")
            wb=npvs._whitebox_block(h[p:p+16])
        else:wb=b""
        values=[raw,(password or "").encode(),wb]
        if identity:
            from decoders.Python.npvs_identity import binary
            values.extend([binary(identity["privateKey"]),binary(identity["publicKey"])])
        lines.append("\t".join(base64.b64encode(v).decode() for v in values))
    process=subprocess.run(["java","-XX:-UsePerfData",str(ROOT/"tests/golden/npvs_protected_oracle.java")],
        input="\n".join(lines)+"\n",text=True,capture_output=True,timeout=45)
    if process.returncode:raise ValueError("Independent JDK verification failed")
    return [json.loads(line) for line in process.stdout.splitlines()]


def document(reference,raw):
    """Rebuild source context and complete layout without production parsers."""
    metadata=json.loads(base64.b64decode(reference["metadata"]))
    records={i:json.loads(base64.b64decode(value)) for i,value in reference["records"]}
    used=set()
    def resolve(node):
        if isinstance(node,dict):return {k:resolve(v) for k,v in node.items()}
        if isinstance(node,list):return [resolve(v) for v in node]
        if type(node) is not int or node==65535 or node not in records:raise ValueError("Reference layout")
        used.add(node);return records[node]
    reconstructed=resolve(records[65535])
    if used!=set(records)-{65535}:raise ValueError("Reference inventory")
    hlen=int.from_bytes(raw[5:9],"big");h=raw[9:9+hlen];nonce=raw[9+hlen:21+hlen];pol=metadata["policy"]
    encode=lambda b:base64.urlsafe_b64encode(b).decode().rstrip("=")
    policy={k:pol.get(k,d) for k,d in (("onlyMobileNetwork",False),("attestationLevel",""),
        ("expiresAt",None),("displayMessage",""),("customServerMessage",""))}
    if pol.get("configVersion",0):policy["configVersion"]=pol["configVersion"]
    source={"v":raw[4],"configId":encode(h[1:17]),"issuedAt":metadata.get("issuedAt",""),
        "creator":{"fp":encode(hashlib.sha256(h[17:50]).digest()),"pk":encode(h[17:50])},"policy":policy,"recipients":None}
    canonical=json.dumps(source,ensure_ascii=False,sort_keys=True,separators=(",",":"))
    context=hashlib.sha256(f"NPVS-v{raw[4]}/source-fields-v1/".encode()+canonical.encode()+nonce).digest()
    if context!=base64.b64decode(reference["context"]):raise ValueError("Reference source context mismatch")
    return {"metadata":metadata,"document":reconstructed}


def embedded(value,depth=0):
    """Independent explicit npvs1 decoding of the reference JSON, not guesses."""
    if depth>64:raise ValueError("Reference nesting")
    if isinstance(value,dict):return {k:embedded(v,depth+1) for k,v in value.items()}
    if isinstance(value,list):return [embedded(v,depth+1) for v in value]
    if not isinstance(value,str) or not value.startswith("npvs1:"):return value
    encoded="".join(value[6:].split())
    text=base64.b64decode(encoded+"="*(-len(encoded)%4),altchars=b"-_",validate=True).decode("utf-8")
    if text.startswith("npvs1:"):return embedded(text,depth+1)
    if text.lstrip().startswith(("{","[")):
        try:return embedded(json.loads(text),depth+1)
        except json.JSONDecodeError:pass
    return text


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("inputs",type=Path,nargs="+")
    p.add_argument("--credentials-stdin",action="store_true")
    p.add_argument("--worker",action="store_true")
    args=p.parse_args();credentials={}
    if args.credentials_stdin:
        incoming=sys.stdin.buffer.read(32769)
        credentials=json.loads(incoming)
        if len(incoming)>32768 or not isinstance(credentials,dict) or set(credentials)-{"password","publicKey"}:
            p.error("Invalid credentials object")
    inputs=[path.read_bytes() for path in args.inputs]
    references=jdk([(raw,credentials.get("password")) for raw in inputs])
    count=fields=pending=0
    for raw,ref in zip(inputs,references,strict=True):
        if ref.get("status")=="PRIVATE_KEY_REQUIRED":
            try:npvs.decode_npvs(raw,public_key=credentials.get("publicKey"))
            except npvs.DecodeError as error:
                if error.code!="PRIVATE_KEY_REQUIRED":raise ValueError("Recipient diagnostic mismatch")
            else:raise ValueError("Recipient unexpectedly opened")
            pending+=1
            continue
        expected=document(ref,raw)
        result=npvs.decode_npvs(raw,password=credentials.get("password"))
        if result!=expected:raise ValueError("Complete raw JSON mismatch")
        complete=npvs.decode_npvs_complete(raw,password=credentials.get("password"))
        if complete!=embedded(expected):raise ValueError("Complete unwrapped JSON mismatch")
        if args.worker:
            from cloud.workers.python.engine import decode_file
            output=decode_file("npvs",raw,credentials={"password":credentials["password"]} if "password" in credentials else None)
            if output["structuredJson"]!=complete or output["isPartial"]:raise ValueError("Complete worker mismatch")
        count+=1;fields+=len(ref["records"])
    print(json.dumps({"completeJdkDocuments":count,"authenticatedJdkRecords":fields,
        "recipientFilesStillRequirePrivateKey":pending,"isolatedWorker":args.worker}))


if __name__=="__main__":main()
