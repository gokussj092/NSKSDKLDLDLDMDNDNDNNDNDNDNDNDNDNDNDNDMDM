#!/usr/bin/env python3
"""Reproduce reviewed APK static inspection; generated code stays in private output."""
import argparse,hashlib,importlib.util,json,subprocess,sys,zipfile
from pathlib import Path
from io import BytesIO
ROOT=Path(__file__).resolve().parents[4]
PACKAGE="core.vpn3jx.xtreme"
HEAP="2200m"
THREADS="3"
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def main():
    p=argparse.ArgumentParser();p.add_argument("private_folder",type=Path);a=p.parse_args();folder=a.private_folder.resolve()
    identity=json.loads((folder/"identity.json").read_text());expected=16
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
    source=out/"sources"
    chunks=source/"org/lsposed/lsparanoid/Deobfuscator$WolfCustomVPN$app.java"
    normalized=folder/"normalized-chunks.java"
    text=chunks.read_text();text=text.replace("chunks = {","chunks = new String[]{",1)
    normalized.write_text(text);normalized.chmod(0o600)
    resolved=folder/"resolved"
    command=[sys.executable,str(ROOT/"scripts/apk_analysis/paranoid_strings.py"),str(source),str(normalized),
             str(resolved),"--call-class","Deobfuscator$WolfCustomVPN$app","--inventory"]
    step=subprocess.run(command,capture_output=True,text=True,timeout=180)
    if step.returncode:raise ValueError("LSPARANOID_RESOLUTION_FAILED")
    report["paranoidStrings"]=json.loads(step.stdout)
    native=folder/"native";native.mkdir(exist_ok=True)
    with zipfile.ZipFile(folder/"distribution.xapk") as outer:
        entry=outer.getinfo("config.armeabi_v7a.apk")
        if entry.file_size>100*1024*1024:raise ValueError("NATIVE_SPLIT_BOUNDS")
        with zipfile.ZipFile(BytesIO(outer.read(entry))) as split:
            info=split.getinfo("lib/armeabi-v7a/libgojni.so")
            if info.file_size>100*1024*1024:raise ValueError("NATIVE_BOUNDS")
            target=native/"libgojni.so";target.write_bytes(split.read(info));target.chmod(0o600)
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    from native_recipe import inspect
    _,report["nativeRecipe"]=inspect(native/"libgojni.so")
    core=resolved/"com/v2ray/ang/util/ConfigUpdate$configUpdate$1.java"
    content=core.read_text()
    if "Libv2ray.cu(this.$current)" not in content:raise ValueError("UPDATER_CHAIN_MISMATCH")
    report["updaterJavaSha256"]=hashlib.sha256(core.read_bytes()).hexdigest()
    path=folder/"static-proof.json";path.write_text(json.dumps(report,indent=2)+"\n");path.chmod(0o600)
    print(json.dumps(report))
if __name__=="__main__":main()

