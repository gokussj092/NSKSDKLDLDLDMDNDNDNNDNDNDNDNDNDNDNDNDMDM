#!/usr/bin/env python3
"""Controlled operator-only QA admission. Never place the code inside the APK."""
from __future__ import annotations
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
from urllib.parse import urlsplit

ROOT=Path(os.environ.get("SPDECODE_HOME","/opt/spdecode"))
CFG=Path(os.environ.get("SPDECODE_CONFIG_DIR","/etc/spdecode"))
ENV=CFG/"cloud.env"
STATE=CFG/"qa-previous.json"
COMPOSE=ROOT/"repo/cloud/compose.yaml"
QA_TTL=4*3600
KEY="spc3:qa:code"
PROVIDER_KEYS=("CLOUD_NUR_FETCH_ENABLED","CLOUD_NUR_CATALOG_URL","CLOUD_EHI_IMPORT_ENABLED")
NUR_ASSET=ROOT/"repo/android/app/src/main/assets/nur_tunnel_server_endpoint.json"

def permitted_catalog():
    """Use the existing audited Android catalog source without logging its URL."""
    try:
        raw=json.loads(NUR_ASSET.read_text(encoding="utf-8"))["catalogUrl"]
        parsed=urlsplit(raw)
    except (OSError,ValueError,KeyError,TypeError):
        raise RuntimeError("NUR catalog asset missing or invalid") from None
    # Mirror cloud/web/lib/c35-provider.mjs approvedUrl. Never allow arbitrary hosts.
    if (not isinstance(raw,str) or len(raw)>2048 or
        parsed.scheme!="https" or parsed.netloc!="strongteam.co" or
        not parsed.path.startswith("/") or len(parsed.path)>256 or
        parsed.query or parsed.fragment or
        parsed.username or parsed.password or parsed.port or
        any(c.isspace() for c in raw)):
        raise RuntimeError("NUR catalog endpoint does not match the approved HTTPS vendor host")
    return raw

def provider_changes(current):
    url=permitted_catalog()
    sign=value(current,"CLOUD_EHI_SIGN_KEY")
    response=value(current,"CLOUD_EHI_RESPONSE_KEY")
    ehi_ready=len(sign)==32 and len(response.encode("utf-8"))==32
    return {
        "CLOUD_NUR_FETCH_ENABLED":"true",
        "CLOUD_NUR_CATALOG_URL":url,
        "CLOUD_EHI_IMPORT_ENABLED":"true" if ehi_ready else "false",
    },ehi_ready

def save_state(data):
    path=STATE.with_suffix(".qa-tmp")
    atomic(path,[json.dumps(data,separators=(",",":"),sort_keys=True)])
    os.replace(path,STATE)
    STATE.chmod(0o600)

def status():
    current=rows()
    until=int(value(current,"CLOUD_QA_EXPIRES_AT") or "0")
    active=value(current,"CLOUD_QA_ENABLED")=="true" and until>time.time()
    print("QA active:",active)
    print("QA expires (UTC epoch):",until)
    print("NUR Server VPN enabled:",value(current,"CLOUD_NUR_FETCH_ENABLED")=="true" and
          bool(value(current,"CLOUD_NUR_CATALOG_URL")))
    print("HTTP Injector Cloud enabled:",value(current,"CLOUD_EHI_IMPORT_ENABLED")=="true")
    # Avoid printing URLs or signing keys, even if the source is publicly tracked.
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
def probe_nur_host_python():
    """Independent HTTPS probe on the VPS host, with the approved NUR URL.
    It does not print endpoints, credentials or the encrypted response body.
    No cross-host redirects or proxy override can redirect it into LAN space.
    """
    import errno
    import socket
    import ssl
    import urllib.error
    import urllib.request

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            return None

    def classify(error):
        raw=getattr(error,"reason",error)
        if isinstance(raw,ssl.SSLError):
            return "TLS"
        number=getattr(raw,"errno",None)
        if number in (errno.ECONNRESET,errno.EPIPE):
            return "CONNECTION_RESET"
        if number==errno.ECONNREFUSED:
            return "CONNECTION_REFUSED"
        if number in (errno.ENETUNREACH,errno.EHOSTUNREACH):
            return "NETWORK_UNREACHABLE"
        if isinstance(raw,(socket.timeout,TimeoutError)):
            return "TIMEOUT"
        if isinstance(raw,socket.gaierror):
            return "DNS"
        return "CONNECTION"

    try:
        url=permitted_catalog()
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        request=urllib.request.Request(
            url,headers={"User-Agent":"NUR TUNNEL VPN",
                         "Accept-Encoding":"identity"})
        with opener.open(request,timeout=10) as response:
            # Read one byte only: never copy or log protected catalog contents.
            byte=response.read(1)
            print(json.dumps({"stage":"host_python","status":"ok" if byte else "failed",
                "code":"HTTP_200" if byte else "EMPTY_BODY"}))
    except urllib.error.HTTPError as error:
        print(json.dumps({"stage":"host_python","status":"failed",
            "code":"HTTP_"+str(error.code)}))
    except (urllib.error.URLError,TimeoutError,OSError) as error:
        print(json.dumps({"stage":"host_python","status":"failed",
            "code":classify(error)}))

def probe_nur():
    """Use production broker and private worker, reporting only safe stages."""
    current=rows()
    expiration=int(value(current,"CLOUD_QA_EXPIRES_AT") or "0")
    if (value(current,"CLOUD_QA_ENABLED")!="true" or expiration<=time.time()
        or not STATE.exists()):
        raise SystemExit("Start a private QA session before probing NUR.")
    javascript=r'''
import {downloadNur,nurConfigured} from "./lib/c35-provider.mjs";
import {fetchWorker} from "./lib/c3-gateway.mjs";
import {settings} from "./lib/c3-config.mjs";
const emit=o=>console.log(JSON.stringify(o));
if(!nurConfigured()){
  emit({stage:"configuration",status:"failed",code:"REMOTE_NOT_CONFIGURED"});
  process.exit(2);
}
let raw;
const fetchStarted=Date.now();
try {
  raw=await downloadNur();
  emit({stage:"download",status:"ok",bytes:raw.length,
    elapsedSeconds:Math.round((Date.now()-fetchStarted)/100)/10});
}catch(error){
  emit({stage:"download",status:"failed",
    code:typeof error?.code==="string"?error.code:"REMOTE_PROVIDER_UNAVAILABLE",
    reason:typeof error?.reason==="string" && /^[A-Z0-9_]{2,32}$/.test(error.reason)?
      error.reason:"UNCLASSIFIED",
    elapsedSeconds:Math.round((Date.now()-fetchStarted)/100)/10});
  process.exit(3);
}
const decodeStarted=Date.now();
try {
  const response=await fetchWorker("catalog",
    {dataBase64:raw.toString("base64")},settings());
  const output=await response.json();
  if(!response.ok){
    emit({stage:"decode",status:"failed",httpStatus:response.status,
      code:output?.error?.code||"ENGINE_UNAVAILABLE",
      elapsedSeconds:Math.round((Date.now()-decodeStarted)/100)/10});
    process.exit(4);
  }
  const parsed=output?.structuredJson;
  emit({stage:"decode",status:"ok",servers:
    Array.isArray(parsed?.Servers)?parsed.Servers.length:null,
    networks:Array.isArray(parsed?.Networks)?parsed.Networks.length:null,
    partial:output.isPartial===true,
    elapsedSeconds:Math.round((Date.now()-decodeStarted)/100)/10});
}catch(error){
  emit({stage:"decode",status:"failed",code:"ENGINE_UNAVAILABLE",
    elapsedSeconds:Math.round((Date.now()-decodeStarted)/100)/10});
  process.exit(5);
}
'''
    try:
        result=compose("exec","-T","web","node","--input-type=module","-e",javascript)
        print(result.stdout,end="")
    except subprocess.CalledProcessError as error:
        if error.stdout:
            print(error.stdout,end="")
            probe_nur_host_python()
        else:
            print("NUR diagnostic failed: check web container availability.")
        raise SystemExit(error.returncode or 1) from None

def main():
    if os.geteuid()!=0:raise SystemExit("Use sudo spdecode qa start|stop|status")
    if len(sys.argv)!=2 or sys.argv[1] not in ("start","stop","status","services","probe-nur"):
        raise SystemExit("Usage: spdecode qa start|stop|status|services|probe-nur")
    action=sys.argv[1]
    old=rows()
    if action=="status":
        status()
        return
    if action=="probe-nur":
        probe_nur()
        return
    if action=="services":
        until=int(value(old,"CLOUD_QA_EXPIRES_AT") or "0")
        if value(old,"CLOUD_QA_ENABLED")!="true" or until<=time.time() or not STATE.exists():
            raise SystemExit("QA is inactive. Start it first using: sudo spdecode qa start")
        state=json.loads(STATE.read_text())
        changes,ehi_ready=provider_changes(old)
        # Capture the original flags before the FIRST activation only.
        for key in PROVIDER_KEYS:
            if key not in state:
                state[key]=value(old,key)
        save_state(state)
        atomic(ENV,replace(old,changes))
        try:
            compose("up","-d","--no-deps","--force-recreate","web")
            if not health():raise RuntimeError("QA API was not ready after service configuration.")
        except Exception:
            atomic(ENV,old)
            try:compose("up","-d","--no-deps","--force-recreate","web")
            except Exception:pass
            raise
        print("NUR Server VPN: ENABLED for existing QA session")
        print("HTTP Injector Cloud:", "ENABLED" if ehi_ready else "NOT CONFIGURED (provider credentials missing)")
        print("Re-use the existing QA code. Android rebuild not required.")
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
        providers,ehi_ready=provider_changes(old)
        changes.update(providers)
        save_state({key:value(old,key) for key in changes})
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
        print("NUR Server VPN: ENABLED during QA")
        print("HTTP Injector Cloud:", "ENABLED" if ehi_ready else "NOT CONFIGURED (provider credentials missing)")
        print("QA CODE:",code)
        print("Expires at UNIX UTC:",until)
        print("Android QA APK: open the separate 'SP-DECODE QA' launcher, enter the code, then open the main app.")
        print("Stop immediately after tests: sudo spdecode qa stop")
    else:
        # Fail closed immediately, even if Redis cleanup fails.
        state=json.loads(STATE.read_text()) if STATE.exists() else {}
        # Preserve unrelated API/maintenance switches when no QA session exists.
        changes={key:state[key] for key in ("CLOUD_API_ENABLED",
            "CLOUD_FORCE_MAINTENANCE",*PROVIDER_KEYS) if key in state}
        changes.update({"CLOUD_QA_ENABLED":"false","CLOUD_QA_EXPIRES_AT":"0"})
        atomic(ENV,replace(old,changes))
        try:
            compose("exec","-T","redis","redis-cli","DEL",KEY)
        except Exception:pass
        compose("up","-d","--no-deps","--force-recreate","web")
        STATE.unlink(missing_ok=True)
        print("QA stopped. Temporary code revoked; previous API/maintenance settings restored.")
if __name__=="__main__":
    main()
