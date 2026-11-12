#!/usr/bin/env python3
"""Reproduce reviewed APK static inspection; generated code stays in private output."""
import argparse,hashlib,importlib.util,json,subprocess,sys,zipfile
from pathlib import Path
from io import BytesIO
ROOT=Path(__file__).resolve().parents[4]
PACKAGE="com.tunneltweak.loyalteams"
HEAP="1600m"
THREADS="2"
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def main():
    p=argparse.ArgumentParser();p.add_argument("private_folder",type=Path);a=p.parse_args();folder=a.private_folder.resolve()
    identity=json.loads((folder/"identity.json").read_text());expected=53
    if identity["package"]!=PACKAGE or identity["versionCode"]!=expected:raise ValueError("UNEXPECTED_APK_IDENTITY")
    if hashlib.sha256((folder/"base.apk").read_bytes()).hexdigest()!=identity["apkSha256"]:raise ValueError("APK_HASH_MISMATCH")
    installer=load("pinned_jadx",ROOT/"scripts/apk_analysis/decompile.py");jar=installer.install()
    out=folder/"jadx";out.mkdir(exist_ok=True)
    with (folder/"jadx.log").open("wb") as log:
        rc=subprocess.run(["java","-Xmx"+HEAP,"-XX:ActiveProcessorCount="+THREADS,"-cp",str(jar),
            "jadx.cli.JadxCLI","--no-res","--decompilation-mode","auto","-j",THREADS,
            "-d",str(out),str(folder/"base.apk")],stdout=log,stderr=subprocess.STDOUT,timeout=300).returncode
    report={"package":PACKAGE,"build":expected,"jadxVersion":installer.VERSION,
            "jadxJarSha256":installer.JAR_SHA256,"jadxExitCode":rc,"apkCodeExecuted":False}
    source=out/"sources/com/tunneltweak/loyalteams"
    hashes={}
    for name in ("ServerConfigManager.java","SecureConfigEncryption.java","ConfigManager.java"):
        target=source/name
        hashes[name]=hashlib.sha256(target.read_bytes()).hexdigest()
    updater=(source/"ServerConfigManager.java").read_text()
    cipher=(source/"SecureConfigEncryption.java").read_text()
    for marker in ('"https://tunneltweak.com/api/servers"','"x-app-version", String.valueOf(getAppVersionCode())','"x-cfg-keyed"'):
        if marker not in updater:raise ValueError("UPDATER_RECIPE_MISMATCH")
    for marker in ('ITERATIONS = 10000','"PBKDF2WithHmacSHA256"','"AES/GCM/NoPadding"','"TunnelTweak-Secure-v1"'):
        if marker not in cipher:raise ValueError("CRYPTO_RECIPE_MISMATCH")
    report["classesSha256"]=hashes
    report["publicCatalogCryptoUnchanged"]=True
    report["requestBuildHeader"]=str(expected)
    path=folder/"static-proof.json";path.write_text(json.dumps(report,indent=2)+"\n");path.chmod(0o600)
    print(json.dumps(report))
if __name__=="__main__":main()

