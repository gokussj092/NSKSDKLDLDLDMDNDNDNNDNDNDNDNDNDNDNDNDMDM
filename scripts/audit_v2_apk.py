#!/usr/bin/env python3
"""Inspect actual APK boundaries without printing payloads or native bytes."""
import argparse
import re
from zipfile import ZipFile

def audit(path,origin):
    with ZipFile(path) as apk:
        dex=b"".join(apk.read(n) for n in apk.namelist() if re.fullmatch(r"classes\d*\.dex",n))
        assert dex,"No DEX"
        for value in [origin.encode(),b"/api/v1/",b"/api/v2/transport"]:
            assert value not in dex,"API address remains in DEX"
        libraries=[n for n in apk.namelist() if n.endswith("/libv7q3.so")]
        assert libraries,"Missing native transport"
        for name in libraries:
            raw=apk.read(name)
            assert raw.startswith(b"\x7fELF"),"Invalid ELF"
            assert b"JNI_OnLoad" in raw,"Missing JNI registration"
            for value in [origin.encode(),b"/api/v1/",b"/api/v2/transport",b"Java_com_ghostdeveloper_"]:
                assert value not in raw,"Unencoded native destination or descriptive JNI export"
    print("V2 APK boundary passed: addresses absent from DEX; encoded native destination and registered JNI present")

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("apk")
    parser.add_argument("--origin",required=True)
    args=parser.parse_args()
    audit(args.apk,args.origin)
