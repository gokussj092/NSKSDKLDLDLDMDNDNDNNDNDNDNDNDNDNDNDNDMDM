#!/usr/bin/env python3
"""Reuse the vetted APKPure acquisition helper, then inspect real APK identity."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,os
from io import BytesIO
from pathlib import Path
import zipfile
from androguard.core.apk import APK
from loguru import logger
logger.disable("androguard")
ROOT=Path(__file__).resolve().parents[4]
SOURCE="https://d.apkpure.net/b/XAPK/core.vpn3jx.xtreme?versionCode=16"
PACKAGE="core.vpn3jx.xtreme"
EXPECTED_BUILD=16
EXPECTED_CERT_SHA1="7d64f9c253c7ef35a0720f6f8a802bd4b920aa3a"

def load_acquirer():
    path=ROOT/"analysis/com.tunneldoom.http/432/tools/acquire.py"
    spec=importlib.util.spec_from_file_location("vetted_acquirer",path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    module.SOURCE=SOURCE  # Fixed per-app URL; existing redirect allowlist unchanged.
    return module

def inspect(data):
    with zipfile.ZipFile(BytesIO(data)) as archive:
        entry=archive.getinfo(PACKAGE+".apk")
        if entry.file_size>100*1024*1024:raise ValueError("BASE_TOO_LARGE")
        raw=archive.read(entry)
    apk=APK(raw,raw=True)
    code=int(apk.get_androidversion_code())
    if apk.get_package()!=PACKAGE or code!=EXPECTED_BUILD:raise ValueError("UNEXPECTED_APK_IDENTITY")
    certificates={certificate.sha1.hex():certificate.sha256.hex()
                  for certificate in apk.get_certificates()}
    if EXPECTED_CERT_SHA1 not in certificates:raise ValueError("SIGNER_DIGEST_MISMATCH")
    return raw,{"package":PACKAGE,"versionName":apk.get_androidversion_name(),"versionCode":code,
        "xapkBytes":len(data),"xapkSha256":hashlib.sha256(data).hexdigest(),
        "apkBytes":len(raw),"apkSha256":hashlib.sha256(raw).hexdigest(),
        "certificateSha256":sorted(certificates.values()),
        "certificateSha1MatchesPreviousDistribution":True,
        "cryptographicApkSignatureVerified":False,"apkCodeExecuted":False}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args();module=load_acquirer()
    args.out.mkdir(parents=True,exist_ok=True);args.out.chmod(0o700)
    candidate=args.out/"distribution.xapk"
    if candidate.is_symlink():raise ValueError("UNSAFE_PRIVATE_INPUT")
    if candidate.is_file():
        with candidate.open("rb") as stream:data=stream.read(module.MAX_BYTES+1)
    else:
        data=module.fetch_xapk();module.save_private(data,candidate)
    raw,result=inspect(data)
    base=args.out/"base.apk"
    if base.is_file():
        if hashlib.sha256(base.read_bytes()).hexdigest()!=result["apkSha256"]:raise ValueError("EXISTING_BASE_MISMATCH")
    else:module.save_private(raw,base)
    (args.out/"identity.json").write_text(json.dumps(result,indent=2)+"\n")
    (args.out/"identity.json").chmod(0o600)
    print(json.dumps(result))
if __name__=="__main__":main()

