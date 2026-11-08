"""Differential validation of native C++ HCX4 against independent Python goldens."""
from __future__ import annotations
import json
import struct
import subprocess
import sys
from tests.golden.http_custom_899 import make_file, PASSWORD, HWID
from decoders.Python.apps.HTTP_Custom.codec import decrypt

def call(exe, data: bytes, password="", hwid=""):
    fields=(password.encode(),hwid.encode(),data)
    frames=b"".join(struct.pack(">I",len(x))+x for x in fields)
    return subprocess.run([exe], input=frames,capture_output=True,check=False)

def check(condition, message):
    if not condition: raise AssertionError(message)

def main(exe):
    passed=0
    for locked in (False,True):
        for protected in (False,True):
            password=PASSWORD if protected else ""
            hwid=HWID if locked else ""
            for carrier in (0,1,2):
                source=make_file(locked=locked,protected=protected,carrier=carrier)
                expected=decrypt(source,password=password or None,hwid=hwid or None)
                result=call(exe,source,password,hwid)
                check(result.returncode==0,(locked,protected,carrier,result.stderr.decode()[:200]))
                actual=json.loads(result.stdout)
                check(actual==expected,(locked,protected,carrier,actual,expected))
                passed+=1
            # Correct keys must reject altered tags in every authenticated layer.
            for where in ("outer","slot","main","profile","hpr","sidecar"):
                if where=="slot" and not locked:continue
                bad=call(exe,make_file(locked=locked,protected=protected,tamper=where),password,hwid)
                check(bad.returncode!=0,(locked,protected,where,"tampered ciphertext accepted"))
                passed+=1
            if protected:
                bad=call(exe,make_file(locked=locked,protected=protected),"incorrect password",hwid)
                check(bad.returncode!=0,"wrong password accepted")
                passed+=1
                missing=call(exe,make_file(locked=locked,protected=protected),"",hwid)
                check(missing.returncode!=0,"missing password accepted")
                passed+=1
            if locked:
                bad=call(exe,make_file(locked=locked,protected=protected),password,"B"*32)
                check(bad.returncode!=0,"wrong HWID accepted")
                passed+=1
                missing=call(exe,make_file(locked=locked,protected=protected),password,"")
                check(missing.returncode!=0,"missing HWID accepted")
                passed+=1
    for invalid in (b"",b"invalid","".encode()+b"\xff"*45):
        check(call(exe,invalid).returncode!=0,"invalid input accepted")
        passed+=1
    print(f"PASS: native HCX4 Python parity and fail-closed checks: {passed} cases")

if __name__=="__main__":
    main(sys.argv[1])
