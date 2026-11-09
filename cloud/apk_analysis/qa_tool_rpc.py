"""F7-A5: authenticated, streaming QA -> separate private tooling worker.

No public endpoint and no Android token. The receiving QA container uses a
separate generated inter-service secret. The remote worker receives only the
verified APK/APKS bytes, never web/HPKE credentials or its persisted journal.
"""
from __future__ import annotations
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import time

MAX_APK=100_000_000
MAX_REPORT=256_000
TOKEN=re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
HEX64=re.compile(r"[0-9a-f]{64}\Z")
NONCE=re.compile(r"[0-9a-f]{32}\Z")


def digest_message(size:int,sha:str,epoch:int,nonce:str,suffix:str)->bytes:
    return f"{size}:{sha}:{epoch}:{nonce}:{suffix}".encode("ascii")


def mac(token:str,size:int,sha:str,epoch:int,nonce:str,suffix:str)->str:
    return hmac.new(token.encode("ascii"),
                    digest_message(size,sha,epoch,nonce,suffix),
                    hashlib.sha256).hexdigest()


def unavailable(status:str)->dict:
    return {"status":status,"jadxExecuted":False,"ghidraExecuted":False,
            "jadx":{"status":"NOT_EXECUTED"},
            "ghidra":{"status":"NOT_EXECUTED"}}


def inspect_remote(source:Path,*,host:str="apk-tools",port:int=8793)->dict:
    token=os.environ.get("SPDECODE_APK_QA_TOOLS_TOKEN","")
    if not TOKEN.fullmatch(token):
        return unavailable("WORKER_NOT_CONFIGURED")
    source=Path(source)
    suffix=source.suffix.lower()
    if suffix not in (".apk",".apks") or not source.is_file() or source.is_symlink():
        return unavailable("WORKER_INVALID_SOURCE")
    size=source.stat().st_size
    if size<=0 or size>MAX_APK:
        return unavailable("WORKER_INVALID_SOURCE")
    sha=hashlib.sha256()
    with source.open("rb") as inp:
        while block:=inp.read(256*1024):
            sha.update(block)
    digest=sha.hexdigest()
    now=int(time.time())
    nonce=secrets.token_hex(16)
    headers={
        "Content-Type":"application/octet-stream",
        "Content-Length":str(size),
        "X-SP-Tool-Hash":digest,
        "X-SP-Tool-Time":str(now),
        "X-SP-Tool-Nonce":nonce,
        "X-SP-Tool-Ext":suffix,
        "X-SP-Tool-Mac":mac(token,size,digest,now,nonce,suffix),
    }
    connection=http.client.HTTPConnection(host,port,timeout=1800)
    try:
        with source.open("rb") as inp:
            connection.request("POST","/analyze",body=inp,headers=headers)
        reply=connection.getresponse()
        raw=reply.read(MAX_REPORT+1)
        if reply.status!=200 or len(raw)>MAX_REPORT:
            return unavailable("WORKER_REQUEST_FAILED")
        response=json.loads(raw)
        if not isinstance(response,dict):
            return unavailable("WORKER_RESPONSE_INVALID")
        if not (isinstance(response.get("status"),str) and
                type(response.get("jadxExecuted")) is bool and
                type(response.get("ghidraExecuted")) is bool and
                isinstance(response.get("jadx"),dict) and
                isinstance(response.get("ghidra"),dict)):
            return unavailable("WORKER_RESPONSE_INVALID")
        # No remote process may assert vendor-method verification.
        response.pop("vendorMethodValidated",None)
        response.pop("credentialsExtracted",None)
        response["isolatedWorker"]=True
        return response
    except (OSError,ValueError,json.JSONDecodeError,http.client.HTTPException):
        return unavailable("WORKER_UNAVAILABLE")
    finally:
        connection.close()
