"""F7 QA APK static-analysis lab: private capability-bound HTTP service.

No public listening port in Compose, no account/billing, no access to worker
secrets or production decoders, and no executing uploaded APK/Dex/ELF.
Only internal V2-attested gateway can call this service, and users must own
the opaque upload capability (bound to the device public signing key).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import threading
import time

from .qa_static import inspect_static

MAX_APK = 96 * 1024 * 1024  # QA cap, not the future paid production quota.
CHUNK = 2 * 1024 * 1024
MAX_POST = 3 * 1024 * 1024
MAX_ACTIVE = 2
JOB_TTL = 3600
RESULT_TTL = 12 * 3600
ROOT = Path(os.environ.get("SPDECODE_APK_QA_ROOT", "/var/lib/spdecode/apkqa"))
HEX32 = re.compile(r"[a-f0-9]{32}\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
TOKEN = re.compile(r"[A-Za-z0-9_-]{43}\Z")
ALLOWED = {"start", "chunk", "finish", "result"}
MUTEX = threading.RLock()


class ApiError(Exception):
    def __init__(self, code:str, status:int=400):
        super().__init__(code)
        self.code=code
        self.status=status


def canonical(obj:dict) -> bytes:
    return (json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode()


def digest(token:str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _json(path:Path) -> dict:
    if path.is_symlink():
        raise ApiError("JOB_UNAVAILABLE",404)
    try:
        content=json.loads(path.read_bytes())
    except (OSError,ValueError):
        raise ApiError("JOB_UNAVAILABLE",404) from None
    if not isinstance(content,dict):raise ApiError("JOB_UNAVAILABLE",404)
    return content


def _atomic(path:Path, value:dict) -> None:
    if path.is_symlink():raise ApiError("JOB_UNAVAILABLE",404)
    tmp=path.with_name("."+path.name+"."+secrets.token_hex(8))
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        with os.fdopen(fd,"wb") as out:
            out.write(canonical(value))
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp,path)
    finally:
        tmp.unlink(missing_ok=True)


def _job(job_id:str):
    if not isinstance(job_id,str) or not HEX32.fullmatch(job_id):
        raise ApiError("JOB_UNAVAILABLE",404)
    folder=ROOT/job_id
    if folder.is_symlink() or not folder.is_dir():
        raise ApiError("JOB_UNAVAILABLE",404)
    return folder


def _authorized(payload:dict):
    folder=_job(payload.get("jobId"))
    state=_json(folder/"state.json")
    key=payload.get("uploadToken")
    owner=payload.get("deviceKeyHash")
    if not isinstance(key,str) or not TOKEN.fullmatch(key) or not isinstance(owner,str) or not HEX64.fullmatch(owner):
        raise ApiError("JOB_UNAVAILABLE",404)
    if not (hmac.compare_digest(digest(key),state.get("tokenDigest",""))
            and hmac.compare_digest(owner,state.get("deviceKeyHash",""))):
        raise ApiError("JOB_UNAVAILABLE",404)
    if time.time() > state["createdAt"] + RESULT_TTL:
        raise ApiError("JOB_EXPIRED",410)
    return folder,state


def _purge(now:float) -> None:
    if not ROOT.exists():return
    for path in ROOT.iterdir():
        if not HEX32.fullmatch(path.name) or path.is_symlink() or not path.is_dir():continue
        try:
            state=_json(path/"state.json")
            ttl=RESULT_TTL if state.get("status") in {"COMPLETED","FAILED","REJECTED"} else JOB_TTL
            if now < state["updatedAt"] + ttl:continue
            for name in ("input.part","report.json","state.json"):
                file=path/name
                if not file.is_symlink():file.unlink(missing_ok=True)
            path.rmdir()
        except (OSError,ValueError,ApiError,KeyError):
            pass


def _start(p:dict) -> dict:
    total=p.get("totalBytes")
    filename=p.get("filename")
    sha=p.get("sha256")
    owner=p.get("deviceKeyHash")
    if not isinstance(total,int) or isinstance(total,bool) or total<=0 or total>MAX_APK:
        raise ApiError("INPUT_TOO_LARGE",413)
    if not isinstance(filename,str) or not re.fullmatch(r"[A-Za-z0-9_. -]{1,100}",filename) or filename.startswith("."):
        raise ApiError("INVALID_FILENAME")
    if Path(filename).suffix.lower() not in {".apk",".apks"}:
        raise ApiError("UNSUPPORTED_FORMAT")
    if not isinstance(sha,str) or not HEX64.fullmatch(sha):
        raise ApiError("INVALID_SHA256")
    if not isinstance(owner,str) or not HEX64.fullmatch(owner):
        raise ApiError("UNAUTHORIZED",401)
    if p.get("consent") is not True or p.get("qaFirstPass") is not True:
        raise ApiError("CONSENT_REQUIRED",403)
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    _purge(time.time())
    active=0
    for path in ROOT.iterdir():
        if path.is_dir() and HEX32.fullmatch(path.name):
            try:
                if _json(path/"state.json").get("status") in {"UPLOADING","PROCESSING"}:active+=1
            except ApiError:
                pass
    if active>=MAX_ACTIVE:raise ApiError("QA_BUSY",429)
    job_id=secrets.token_hex(16)
    folder=ROOT/job_id
    folder.mkdir(mode=0o700,exist_ok=False)
    secret=secrets.token_urlsafe(32)
    now=time.time()
    state={"jobId":job_id,"deviceKeyHash":owner,
           "tokenDigest":digest(secret),"filename":filename,"totalBytes":total,"sha256":sha,
           "status":"UPLOADING","receivedBytes":0,"nextChunk":0,"chunkDigests":[],
           "createdAt":now,"updatedAt":now}
    _atomic(folder/"state.json",state)
    return {"jobId":job_id,"uploadToken":secret,"chunkBytes":CHUNK,
            "maxBytes":MAX_APK,"expiresIn":JOB_TTL,"status":"UPLOADING"}


def _chunk(p:dict) -> dict:
    folder,state=_authorized(p)
    if state["status"]!="UPLOADING":raise ApiError("INVALID_STATE",409)
    index=p.get("index")
    content=p.get("dataBase64")
    if (not isinstance(index,int) or isinstance(index,bool) or index<0
        or not isinstance(content,str) or len(content)>4*((CHUNK+2)//3)+8):
        raise ApiError("INVALID_CHUNK")
    try:
        data=base64.b64decode(content,validate=True)
    except (ValueError,base64.binascii.Error):
        raise ApiError("INVALID_CHUNK") from None
    if not data or len(data)>CHUNK or base64.b64encode(data).decode()!=content:
        raise ApiError("INVALID_CHUNK")
    hash_value=hashlib.sha256(data).hexdigest()
    if hash_value!=p.get("chunkSha256"):raise ApiError("CHUNK_HASH_MISMATCH",422)
    if index<state["nextChunk"]:
        if state["chunkDigests"][index] != hash_value:
            raise ApiError("CHUNK_REPLAY_MISMATCH",409)
        return {"status":"UPLOADING","nextChunk":state["nextChunk"],
                "receivedBytes":state["receivedBytes"]}
    if index!=state["nextChunk"] or state["receivedBytes"]+len(data)>state["totalBytes"]:
        raise ApiError("CHUNK_OUT_OF_ORDER",409)
    file=folder/"input.part"
    if file.is_symlink():raise ApiError("JOB_UNAVAILABLE",404)
    fd=os.open(file,os.O_RDWR|os.O_CREAT|getattr(os,"O_NOFOLLOW",0),0o600)
    try:
        with os.fdopen(fd,"r+b") as out:
            out.truncate(state["receivedBytes"])
            out.seek(state["receivedBytes"])
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
    state["receivedBytes"]+=len(data)
    state["nextChunk"]+=1
    state["chunkDigests"].append(hash_value)
    state["updatedAt"]=time.time()
    _atomic(folder/"state.json",state)
    return {"status":"UPLOADING","nextChunk":state["nextChunk"],
            "receivedBytes":state["receivedBytes"]}


def _process(job_id:str) -> None:
    folder=ROOT/job_id
    try:
        state=_json(folder/"state.json")
        result=inspect_static(folder/("input"+Path(state["filename"]).suffix.lower()))
        status="COMPLETED"
    except Exception:
        result={"schemaVersion":1,"status":"FAILED","error":"STATIC_INSPECTION_FAILED",
                "evidence":"NONE"}
        status="FAILED"
    with MUTEX:
        try:
            _atomic(folder/"report.json",result)
            state=_json(folder/"state.json")
            state["status"]=status
            state["updatedAt"]=time.time()
            _atomic(folder/"state.json",state)
        finally:
            (folder/"input.apk").unlink(missing_ok=True)
            (folder/"input.apks").unlink(missing_ok=True)


def _finish(p:dict) -> dict:
    folder,state=_authorized(p)
    if state["status"]=="PROCESSING":
        return {"status":"PROCESSING","jobId":state["jobId"]}
    if state["status"]!="UPLOADING":raise ApiError("INVALID_STATE",409)
    if state["receivedBytes"]!=state["totalBytes"]:raise ApiError("UPLOAD_INCOMPLETE",409)
    file=folder/"input.part"
    if file.is_symlink() or not file.exists():raise ApiError("UPLOAD_INCOMPLETE",409)
    hashed=hashlib.sha256()
    with file.open("rb") as src:
        while chunk:=src.read(CHUNK):hashed.update(chunk)
    if hashed.hexdigest()!=state["sha256"]:
        state["status"]="REJECTED";state["updatedAt"]=time.time()
        _atomic(folder/"state.json",state)
        file.unlink(missing_ok=True)
        raise ApiError("UPLOAD_HASH_MISMATCH",422)
    suffix=Path(state["filename"]).suffix.lower()
    file.rename(folder/("input"+suffix))
    state["status"]="PROCESSING";state["updatedAt"]=time.time()
    _atomic(folder/"state.json",state)
    thread=threading.Thread(target=_process,args=(state["jobId"],),daemon=True)
    thread.start()
    return {"status":"PROCESSING","jobId":state["jobId"]}


def _result(p:dict) -> dict:
    folder,state=_authorized(p)
    base={"status":state["status"],"jobId":state["jobId"],
          "receivedBytes":state["receivedBytes"],"totalBytes":state["totalBytes"]}
    if state["status"] in {"COMPLETED","FAILED"}:
        base["report"]=_json(folder/"report.json")
    return base


def dispatch(action:str,payload:dict) -> dict:
    if action not in ALLOWED or not isinstance(payload,dict):
        raise ApiError("INVALID_REQUEST")
    with MUTEX:
        if action=="start":return _start(payload)
        if action=="chunk":return _chunk(payload)
        if action=="finish":return _finish(payload)
        return _result(payload)


class Handler(BaseHTTPRequestHandler):
    protocol_version="HTTP/1.0"
    server_version="SPDecodeApkQA/1"
    sys_version=""
    def log_message(self,*args):pass
    def do_GET(self):
        if self.path!="/health":return self.reply(404,{"error":"NOT_FOUND"})
        return self.reply(200,{"service":"spdecode-apk-qa","status":"ok"})
    def do_POST(self):
        action=self.path.removeprefix("/internal/qa/")
        expected=os.environ.get("SPDECODE_APK_QA_INTERNAL_TOKEN","")
        supplied=self.headers.get("x-sp-apk-internal","")
        if (len(expected)<32 or len(supplied)!=len(expected)
            or not hmac.compare_digest(supplied,expected)):
            return self.reply(401,{"error":"UNAUTHORIZED"})
        if action not in ALLOWED:return self.reply(404,{"error":"NOT_FOUND"})
        try:
            length=int(self.headers.get("content-length","-1"))
            if length<2 or length>MAX_POST:raise ApiError("INPUT_TOO_LARGE",413)
            payload=json.loads(self.rfile.read(length))
            result=dispatch(action,payload)
            return self.reply(200,result)
        except ApiError as exc:
            return self.reply(exc.status,{"error":exc.code})
        except (ValueError,KeyError,TypeError):
            return self.reply(400,{"error":"INVALID_REQUEST"})
        except Exception:
            return self.reply(503,{"error":"SERVICE_UNAVAILABLE"})
    def reply(self,status:int,body:dict):
        data=canonical(body)
        self.send_response(status)
        self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length",str(len(data)))
        self.send_header("Cache-Control","no-store")
        self.send_header("X-Content-Type-Options","nosniff")
        self.end_headers()
        self.wfile.write(data)


def main():
    if len(os.environ.get("SPDECODE_APK_QA_INTERNAL_TOKEN",""))<32:
        raise RuntimeError("APK_QA_INTERNAL_TOKEN_NOT_CONFIGURED")
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    server=ThreadingHTTPServer(("0.0.0.0",8792),Handler)
    server.serve_forever(poll_interval=0.2)


if __name__=="__main__":main()
