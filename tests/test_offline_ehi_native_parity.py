"""Native EHI bypass and Argon2id/XChaCha20 differential test."""
from __future__ import annotations
import json
import struct
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.android_ehi_complete_fixture import make as bypass
from scripts.android_ehi_standard_fixture import make as standard
from decoders.Python.HTTPINJECTOR import EHIDecryptor

def invoke(exe,raw):
    return subprocess.run([exe],input=struct.pack(">I",len(raw))+raw,capture_output=True)

def require(cond,reason):
    if not cond:raise AssertionError(reason)

def main(exe):
    count=0
    original,_,expected=bypass()
    result=invoke(exe,original)
    require(result.returncode==0,("bypass",result.stderr.decode(errors="replace")[:300]))
    require(json.loads(result.stdout)==expected,("bypass JSON differs",result.stdout[:300]))
    count+=1
    # Tamper an authenticated CBC envelope until native returns no output.
    corrupt=bytearray(original);corrupt[-11]^=0x40
    result=invoke(exe,corrupt)
    require(result.returncode!=0,"bypass corrupt padding accepted")
    count+=1
    original,formatted=standard()
    result=invoke(exe,original)
    require(result.returncode==0,("standard",result.stderr.decode(errors="replace")[:300]))
    obj=json.loads(result.stdout)
    require(obj=={
        "serverHost":"example.org",
        "serverPort":443,
        "configMessage":"Synthetic EHI standard variant",
        "profileNote":"synthetic-parity-test",
    },("standard mismatch",obj))
    count+=1
    bad=bytearray(original);bad[-20]^=0x40
    require(invoke(exe,bad).returncode!=0,"standard corrupted file accepted")
    count+=1
    for raw in (b"",b"EHI",b"\xff"*100,original[:40],original+b"\0"*4096):
        require(invoke(exe,raw).returncode!=0,("invalid accepted",len(raw)))
        count+=1
    print(f"PASS: native HTTP Injector AES-CBC, XXTEA, Argon2id, XChaCha and recursive field parity: {count} checks")

if __name__=="__main__":
    main(sys.argv[1])
