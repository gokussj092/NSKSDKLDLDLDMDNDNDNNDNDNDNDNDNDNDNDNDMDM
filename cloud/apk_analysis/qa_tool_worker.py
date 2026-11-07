"""Private F7 APK tooling HTTP worker. No public port or uploaded code execution.

One work item at a time, authenticated via an HMAC over length, SHA256,
timestamp and nonce, with a bounded streaming upload and a revalidated APK
structure. Temporary data exists only in the separate worker's scratch.
"""
from __future__ import annotations
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import tempfile
import threading
import time

from .input_gate import GateError, inspect_input
from .qa_tool_rpc import MAX_APK, MAX_REPORT, TOKEN, HEX64, NONCE, mac
from .qa_tooling import inspect_tooling

BUSY=threading.Lock()
NONCES={}
NONCE_LOCK=threading.Lock()


def auth(headers,secret:str)->tuple[int,str]|None:
    if not TOKEN.fullmatch(secret):return None
    raw_size=headers.get("Content-Length","")
    raw_time=headers.get("X-SP-Tool-Time","")
    suffix=headers.get("X-SP-Tool-Ext","")
    sha=headers.get("X-SP-Tool-Hash","")
    nonce=headers.get("X-SP-Tool-Nonce","")
    supplied=headers.get("X-SP-Tool-Mac","")
    if (not re.fullmatch(r"[0-9]{1,9}",raw_size) or
        not re.fullmatch(r"[0-9]{9,12}",raw_time) or
        not HEX64.fullmatch(sha) or not NONCE.fullmatch(nonce) or
        not HEX64.fullmatch(supplied) or suffix not in (".apk",".apks") or
        headers.get("Content-Type")!="application/octet-stream"):
        return None
    size=int(raw_size);stamp=int(raw_time);now=int(time.time())
    if not 0<size<=MAX_APK or abs(now-stamp)>120:return None
    if not hmac.compare_digest(supplied,mac(secret,size,sha,stamp,nonce,suffix)):
        return None
    with NONCE_LOCK:
        for key,expiry in list(NONCES.items()):
            if expiry<=now:NONCES.pop(key,None)
        if nonce in NONCES:return None
        NONCES[nonce]=now+240
    return size,suffix


class Handler(BaseHTTPRequestHandler):
    protocol_version="HTTP/1.1"
    def log_message(self,*args):
        # Never log the path, headers, authenticated identifiers or APK data.
        pass

    def respond(self,code:int,content:dict):
        payload=json.dumps(content,ensure_ascii=True,separators=(",",":")).encode()
        if len(payload)>MAX_REPORT:
            payload=b'{"error":"TOOL_REPORT_TOO_LARGE"}';code=500
        self.send_response(code)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(payload)))
        self.send_header("Cache-Control","no-store")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path!="/health":return self.respond(404,{"error":"NOT_FOUND"})
        return self.respond(200,{"status":"ready"})

    def do_POST(self):
        if self.path!="/analyze":return self.respond(404,{"error":"NOT_FOUND"})
        secret=os.environ.get("SPDECODE_APK_QA_TOOLS_TOKEN","")
        checked=auth(self.headers,secret)
        if checked is None:return self.respond(401,{"error":"UNAUTHORIZED"})
        if not BUSY.acquire(blocking=False):
            return self.respond(409,{"error":"WORKER_BUSY"})
        try:
            # A peer that stops sending must not hold the single worker forever.
            self.connection.settimeout(90)
            size,suffix=checked
            folder=Path(os.environ.get("SPDECODE_APK_QA_TOOLS_SCRATCH","/analysis"))
            with tempfile.TemporaryDirectory(prefix="job-",dir=folder) as td:
                source=Path(td)/("input"+suffix)
                digest=hashlib.sha256()
                remaining=size
                with source.open("xb") as dst:
                    while remaining:
                        chunk=self.rfile.read(min(256*1024,remaining))
                        if not chunk:
                            return self.respond(400,{"error":"INCOMPLETE_UPLOAD"})
                        remaining-=len(chunk)
                        digest.update(chunk)
                        dst.write(chunk)
                if not hmac.compare_digest(digest.hexdigest(),
                                            self.headers.get("X-SP-Tool-Hash","")):
                    return self.respond(422,{"error":"HASH_MISMATCH"})
                try:
                    inspect_input(source)
                except (ValueError,GateError,OSError):
                    return self.respond(422,{"error":"PACKAGE_INVALID"})
                tooling=inspect_tooling(source,{})
                # Keep technical stage findings, not decompiled source or logs.
                tooling.pop("vendorMethodValidated",None)
                tooling.pop("credentialsExtracted",None)
                return self.respond(200,tooling)
        except (OSError,ValueError,RuntimeError):
            return self.respond(500,{"error":"TOOL_WORKER_FAILED"})
        finally:
            BUSY.release()


def main():
    if not TOKEN.fullmatch(os.environ.get("SPDECODE_APK_QA_TOOLS_TOKEN","")):
        raise SystemExit("MISSING_PRIVATE_TOOL_SECRET")
    scratch=Path(os.environ.get("SPDECODE_APK_QA_TOOLS_SCRATCH","/analysis"))
    if not scratch.is_dir() or scratch.is_symlink():
        raise SystemExit("MISSING_PRIVATE_SCRATCH")
    server=ThreadingHTTPServer(("0.0.0.0",8793),Handler)
    server.daemon_threads=True
    server.serve_forever(poll_interval=.5)


if __name__=="__main__":main()
