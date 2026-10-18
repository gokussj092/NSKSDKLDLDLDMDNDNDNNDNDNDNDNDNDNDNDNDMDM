#!/usr/bin/env python3
"""Controlled operator-only QA admission. Never place the code inside the APK."""
from __future__ import annotations
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time

ROOT=Path(os.environ.get("SPDECODE_HOME","/opt/spdecode"))
CFG=Path(os.environ.get("SPDECODE_CONFIG_DIR","/etc/spdecode"))
ENV=CFG/"cloud.env"
STATE=CFG/"qa-previous.json"
COMPOSE=ROOT/"repo/cloud/compose.yaml"
QA_TTL=4*3600
KEY="spc3:qa:code"
def run(*args,stdin=None,quiet=True):
    return subprocess.run(args,input=stdin,text=True,check=True,
        stdout=subprocess.PIPE if quiet else None,stderr=subprocess.PIPE if quiet else None)
def compose(*args):
    return run("docker","compose","--project-name","spdecode",
               "--env-file",str(ENV),"-f",str(COMPOSE),*args)
def rows():
    return ENV.read_text().splitlines()
def value(lines,key):
    for line in lines:
        if line.startswith(key+"="):
            return line.split("=",1)[1].strip().strip("\\\"'")
    return ""
def replace(lines,entries):
    # Only replaces the named safe, unquoted scalar environment keys.
    return [line for line in lines if line.split("=",1)[0] not in entries]+[
        f"{key}={v}" for key,v in entries.items()]
def atomic(path,lines):
    temp=path.with_suffix(".qa-tmp")
    fd=os.open(str(temp),os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,"w") as out:
        out.write("\n".join(lines)+"\n")
        out.flush();os.fsync(out.fileno())
    os.replace(temp,path)
    os.chmod(path,0o600)
def health():
    for _ in range(12):
        try:
            import urllib.request
            with urllib.request.urlopen("http://127.0.0.1:3000/api/v1/ready",timeout=3) as r:
                if r.status==200:return True
        except Exception:
            pass
        time.sleep(2)
    return False
def main():
    if os.geteuid()!=0:raise SystemExit("Use sudo spdecode qa start|stop|status")
    if len(sys.argv)!=2 or sys.argv[1] not in ("start","stop","status"):
        raise SystemExit("Usage: spdecode qa start|stop|status")
    action=sys.argv[1]
    old=rows()
    if action=="status":
        until=int(value(old,"CLOUD_QA_EXPIRES_AT") or "0")
        print("QA active:",value(old,"CLOUD_QA_ENABLED")=="true" and until>time.time())
        print("QA expires (UTC epoch):",until)
        return
    if action=="start":
        if STATE.exists():
            raise SystemExit("QA state already exists. Use 'sudo spdecode qa stop' first.")
        signing=value(old,"CLOUD_SESSION_SIGNING_KEY")
        token=value(old,"CLOUD_WORKER_TOKEN")
        if len(signing)<32 or len(token)<32 or value(old,"CLOUD_TRUST_PROXY")!="true":
            raise SystemExit("Missing worker or session secrets / trusted reverse proxy.")
        code="spqa-"+secrets.token_urlsafe(36)
        digest=hmac.new(signing.encode(),code.encode(),hashlib.sha256).hexdigest()
        until=int(time.time())+QA_TTL
        changes={"CLOUD_QA_ENABLED":"true","CLOUD_QA_EXPIRES_AT":str(until),
                 "CLOUD_API_ENABLED":"true","CLOUD_FORCE_MAINTENANCE":"false"}
        STATE.write_text(json.dumps({key:value(old,key) for key in changes}))
        STATE.chmod(0o600)
        try:
            atomic(ENV,replace(old,changes))
            compose("up","-d","--no-deps","--force-recreate","web")
            # Never pass the plaintext QA code to Docker commands or store it in Redis.
            compose("exec","-T","redis","redis-cli","SET",KEY,digest,"EX",str(QA_TTL))
            if not health():raise RuntimeError("Cloud readiness still fails: inspect worker and Redis.")
        except Exception:
            atomic(ENV,old)
            try:
                compose("exec","-T","redis","redis-cli","DEL",KEY)
                compose("up","-d","--no-deps","--force-recreate","web")
            except Exception:pass
            STATE.unlink(missing_ok=True)
            raise
        print("QA ENABLED for four hours. Save this code privately; it is not stored in plaintext.")
        print("QA CODE:",code)
        print("Expires at UNIX UTC:",until)
        print("Android QA APK: Settings > Cloud QA > Enter code. Do not distribute the code.")
        print("Stop immediately after tests: sudo spdecode qa stop")
    else:
        # Fail closed immediately, even if Redis cleanup fails.
        state=json.loads(STATE.read_text()) if STATE.exists() else {}
        changes={key:state.get(key,"false" if key!="CLOUD_QA_EXPIRES_AT" else "0")
                 for key in ("CLOUD_QA_ENABLED","CLOUD_QA_EXPIRES_AT",
                             "CLOUD_API_ENABLED","CLOUD_FORCE_MAINTENANCE")}
        changes["CLOUD_QA_ENABLED"]="false"
        changes["CLOUD_QA_EXPIRES_AT"]="0"
        atomic(ENV,replace(old,changes))
        try:
            compose("exec","-T","redis","redis-cli","DEL",KEY)
        except Exception:pass
        compose("up","-d","--no-deps","--force-recreate","web")
        STATE.unlink(missing_ok=True)
        print("QA stopped. Temporary code revoked; previous API/maintenance settings restored.")
if __name__=="__main__":
    main()
