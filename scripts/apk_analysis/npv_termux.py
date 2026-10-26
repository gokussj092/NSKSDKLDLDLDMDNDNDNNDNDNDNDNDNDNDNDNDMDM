#!/usr/bin/env python3
"""NPV recipient utility: generate, decode, or capture one owner-imported file.

Standalone bundle includes npvs.py, npvs_identity.py and the scoped JS observer.
Capture requires a working Frida CLI/client and a matching root frida-server
listening on loopback. Does not install binaries or extract hardware keys.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import time

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
if (ROOT/"decoders/Python").is_dir():sys.path.insert(0,str(ROOT/"decoders/Python"))
import npvs
import npvs_identity as identities

PREFIX="SPDECODE_NPV_CAPTURE "


def collect(raw:bytes,candidate:dict) -> dict:
    if candidate.get("kind")=="private-pkcs8":
        if set(candidate)!={"kind","fileSha256","fingerprint","privateKey"} or candidate["fileSha256"]!=hashlib.sha256(raw).hexdigest():
            raise ValueError("Wrong capture")
        from Crypto.PublicKey import ECC
        key=ECC.import_key(identities.binary(candidate["privateKey"]))
        public=key.public_key().export_key(format="SEC1",compress=True)
        candidate={"schema":identities.SCHEMA,"kind":"keypair","source":"captured","curve":"P-256",
            "fingerprint":candidate["fingerprint"],"publicKey":identities.encode(public),
            "privateKey":candidate["privateKey"]}
    identity=identities.normalize(candidate)
    # Verify signature, recipient unwrap, metadata, every scalar and inventory.
    npvs.decode_npvs_complete(raw,recipient_key=identity)
    return identity


def capture(raw:bytes,pid:int,seconds:int) -> dict:
    info=npvs.inspect_npvs(raw)
    if info["mode"]!=0:raise ValueError("This file has no recipient key requirement")
    script=(HERE/"npv_recipient_capture.js").read_text().replace('__TARGET_SHA256__',hashlib.sha256(raw).hexdigest())
    lines=queue.Queue(maxsize=256)
    with tempfile.TemporaryDirectory(prefix="npv-owner-") as folder:
        hook=Path(folder)/"capture.js";hook.write_text(script);hook.chmod(0o600)
        process=subprocess.Popen(["frida","-H","127.0.0.1:27042","-p",str(pid),"-l",str(hook),"-q","-t",str(seconds)],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
        def read():
            try:
                while True:
                    line=process.stdout.readline(32769)
                    if not line:break
                    if len(line)>32768:continue
                    try:lines.put(line,timeout=1)
                    except queue.Full:pass
            finally:
                try:lines.put(None,timeout=1)
                except queue.Full:pass
        reader=threading.Thread(target=read,daemon=True);reader.start()
        print("Abre NPV e importa el archivo indicado. La captura solo se guarda tras verificar el descifrado.")
        deadline=time.monotonic()+seconds
        ready=False
        try:
            while time.monotonic()<deadline:
                try:line=lines.get(timeout=1)
                except queue.Empty:continue
                if line is None:break
                if "NPV_CAPTURE_READY" in line:
                    ready=True;print("Observador listo; importa ahora el archivo en NPV.")
                if PREFIX in line:
                    return collect(raw,json.loads(line.split(PREFIX,1)[1]))
        finally:
            process.terminate()
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
            process.stdout.close();reader.join(timeout=2)
        print("No hubo importación verificable del archivo indicado." if ready else
            "Frida no inició el observador: revisa PID, versión 124.0.37/577, Java bridge y servidor root.",file=sys.stderr)
        raise ValueError("Capture unavailable")


def bounded(path:Path,maximum:int):
    with path.open("rb") as stream:raw=stream.read(maximum+1)
    if len(raw)>maximum:raise ValueError("File exceeds limit")
    return raw


def save(path:Path,value:dict):
    data=json.dumps(value,ensure_ascii=False,indent=2)+"\n"
    with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"w",encoding="utf-8") as stream:stream.write(data)


def main():
    parser=argparse.ArgumentParser(description=__doc__);commands=parser.add_subparsers(dest="command",required=True)
    generate=commands.add_parser("generate");generate.add_argument("-o",type=Path,required=True)
    decode=commands.add_parser("decode");decode.add_argument("input",type=Path);decode.add_argument("--identity",type=Path);decode.add_argument("-o",type=Path,required=True)
    observer=commands.add_parser("capture");observer.add_argument("input",type=Path);observer.add_argument("--pid",type=int,required=True)
    observer.add_argument("--seconds",type=int,default=120);observer.add_argument("-o",type=Path,required=True)
    args=parser.parse_args()
    try:
        if args.o.exists():raise ValueError("Output already exists; choose a new filename")
        if args.command=="generate":result=identities.generate()
        else:
            raw=bounded(args.input,4*1024*1024)
            if args.command=="capture":
                if args.pid<=0 or not 10<=args.seconds<=600:raise ValueError("Invalid PID/duration")
                result=capture(raw,args.pid,args.seconds)
            else:
                identity=identities.normalize(bounded(args.identity,16384).decode()) if args.identity else None
                result=npvs.decode_npvs_complete(raw,recipient_key=identity)
        save(args.o,result);print("Guardado correctamente; permisos 0600.")
        return 0
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        # No material, exception contents or third-party payloads in error output.
        code=error.code if isinstance(error,npvs.DecodeError) else "CAPTURE_OR_INPUT_FAILED"
        print("No se guardó ningún resultado: "+code,file=sys.stderr);return 1
    except KeyboardInterrupt:return 130


if __name__=="__main__":raise SystemExit(main())
