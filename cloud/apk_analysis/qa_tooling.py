"""Optional resource-gated JADX/Ghidra static tooling for F7 APK QA.

Not enabled on small VPS; isolated, offline, preinstalled toolchain only.
A tool returncode is evidence that analysis ran, not evidence of a
working APK decryptor or of the target app's cryptographic method.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import zipfile
from .qa_jadx_refs import scan_jadx_sources
from .qa_tool_rpc import inspect_remote

JADX_JAR=Path("/opt/spdecode/scripts/apk_analysis/cache/jadx-1.5.6-all.jar")
JADX_SHA256="fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b"
MAX_TOOL_APK=100*1000*1000
MAX_GHIDRA_LIBS=3
MIN_MEMORY=3*1024**3
GHIDRA_SCRIPT=Path("/opt/spdecode/cloud/apk_analysis/SpDecodeGhidraReport.java")
ID=re.compile(r"[0-9a-f]{32}\Z")


def _memory_limit()->int:
    """Read the container's enforced memory limit, not the host's free RAM."""
    for name in ("/sys/fs/cgroup/memory.max",
                 "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        try:
            raw=Path(name).read_text().strip()
            if raw!="max":
                amount=int(raw)
                if 0<amount<1<<50:return amount
        except (OSError,ValueError):pass
    return 0  # Unknown means DENY.


def _verified_jadx()->bool:
    try:
        if not JADX_JAR.is_file() or JADX_JAR.is_symlink():
            return False
        digest=hashlib.sha256()
        with JADX_JAR.open("rb") as src:
            while block:=src.read(1024*1024):digest.update(block)
        return digest.hexdigest()==JADX_SHA256
    except OSError:
        return False


def _run(command:list[str],*,cwd:Path,timeout:int,env:dict,
         logfile:Path)->bool:
    # No shell, no APK-controlled argument strings, no stdout in JSON/logs.
    with logfile.open("wb") as log:
        try:
            child=subprocess.Popen(command,cwd=cwd,env=env,
                stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                start_new_session=True)
        except OSError:
            return False
        try:
            return child.wait(timeout=timeout)==0
        except subprocess.TimeoutExpired:
            # Ghidra analyzeHeadless is a launcher. Kill the entire session,
            # not just the shell parent, so no orphan Java process survives.
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            try:child.wait(timeout=10)
            except subprocess.TimeoutExpired:pass
            return False


def _base_and_libs(source:Path,dest:Path):
    """Extract one base APK and at most three bounded ELF candidates."""
    total=0
    splits=[]
    if source.suffix.lower()==".apk":
        base=source
        splits=[source]
    else:
        base=dest/"base.apk"
        with zipfile.ZipFile(source) as outer:
            selected=[x for x in outer.infolist() if x.filename=="base.apk"]
            if len(selected)!=1:raise ValueError("APKS_BASE_NOT_UNIQUE")
            item=selected[0]
            if item.file_size>MAX_TOOL_APK:raise ValueError("BASE_TOO_LARGE")
            with outer.open(item) as inp,base.open("xb") as out:
                count=0
                while block:=inp.read(256*1024):
                    count+=len(block)
                    if count>item.file_size:raise ValueError("SPLIT_BOUNDS")
                    out.write(block)
                if count!=item.file_size:raise ValueError("SPLIT_TRUNCATED")
            splits=[base]
            # Limit additional target splits and do not retain them after work.
            for item in sorted(outer.infolist(),key=lambda z:z.filename):
                if len(splits)>=8:break
                if not item.filename.startswith("split_config.") or not item.filename.endswith(".apk"):
                    continue
                if "/" in item.filename or item.file_size>MAX_TOOL_APK:continue
                split=dest/item.filename
                with outer.open(item) as inp, split.open("xb") as out:
                    copied=0
                    while block:=inp.read(256*1024):
                        copied+=len(block)
                        if copied>item.file_size:raise ValueError("SPLIT_BOUNDS")
                        out.write(block)
                    if copied!=item.file_size:raise ValueError("SPLIT_TRUNCATED")
                splits.append(split)
    binaries=[]
    def priority(item):
        name=item.filename.rsplit("/",1)[-1].lower()
        system=any(k in name for k in ("conscrypt","datastore","c++_shared",
                                        "firebase","sqlite","crashlytics"))
        domain=any(k in name for k in ("vpn","hysteria","tun","tunnel",
                                        "config","crypto","tls"))
        return (1 if system else 0,0 if domain else 1,-item.file_size)
    for split in splits:
        with zipfile.ZipFile(split) as archive:
            candidates=sorted((entry for entry in archive.infolist() if
                entry.filename.startswith("lib/") and
                entry.filename.endswith(".so") and
                52<=entry.file_size<=32*1024*1024),key=priority)
            for info in candidates:
                if len(binaries)>=MAX_GHIDRA_LIBS:break
                # Only a fixed, private basename is written, never an APK path.
                native=dest/("native-"+str(len(binaries))+".so")
                with archive.open(info) as inp,native.open("xb") as out:
                    size=0
                    while block:=inp.read(256*1024):
                        size+=len(block)
                        if size>info.file_size:raise ValueError("ELF_BOUNDS")
                        out.write(block)
                    if size!=info.file_size:raise ValueError("ELF_TRUNCATED")
                binaries.append(native)
    return base,binaries


def inspect_tooling(source:Path,report:dict)->dict:
    """One optional attempt *after* the full upload hash and ZIP gate."""
    if os.environ.get("SPDECODE_APK_QA_TOOLS_REMOTE")=="enabled":
        return inspect_remote(source)
    state={"status":"NOT_ENABLED","jadxExecuted":False,
           "ghidraExecuted":False,"jadx":{"status":"NOT_ENABLED"},
           "ghidra":{"status":"NOT_ENABLED"}}
    if (os.environ.get("SPDECODE_APK_QA_TOOL_MODE")!="enabled" or
            os.environ.get("SPDECODE_APK_QA_TOOLS_REVIEWED")!="true"):
        return state
    if _memory_limit()<MIN_MEMORY:
        state["status"]="INSUFFICIENT_CONTAINER_MEMORY"
        return state
    if not _verified_jadx():
        state["status"]="JADX_NOT_PRELOADED_OR_HASH_MISMATCH"
        return state
    # Ghidra can be absent without invalidating the actual JADX result.
    home=Path(os.environ.get("SPDECODE_APK_QA_GHIDRA_HOME","/opt/ghidra"))
    headless=home/"support/analyzeHeadless"
    # The tool executable itself must match an operator-reviewed SHA-256.
    # This is an additional guard, not validation of the whole installation.
    expected=os.environ.get("SPDECODE_APK_QA_GHIDRA_HEADLESS_SHA256","")
    if not expected:
        manifest=GHIDRA_SCRIPT.with_name("ghidra-headless.sha256")
        if manifest.is_file() and not manifest.is_symlink():
            expected=manifest.read_text("ascii").strip()
    ghidra_ready=(bool(re.fullmatch(r"[a-f0-9]{64}",expected)) and
                  home.is_dir() and not home.is_symlink() and
                  headless.is_file() and not headless.is_symlink() and
                  GHIDRA_SCRIPT.is_file() and
                  hashlib.sha256(headless.read_bytes()).hexdigest()==expected)
    with tempfile.TemporaryDirectory(prefix=".apkqa-tools-",dir=source.parent) as td:
        scratch=Path(td)
        base,libs=_base_and_libs(source,scratch)
        # Java writes only to ephemeral per-job workspace; no network and
        # no permission to the decoder worker, host keys, Redis or Docker.
        # A minimal fixed environment. Never copy the service's internal
        # inter-container credential or unrelated cloud secrets into tools.
        env={"PATH":"/opt/java/openjdk/bin:/usr/local/bin:/usr/bin:/bin",
             "JAVA_HOME":"/opt/java/openjdk",
             "HOME":str(scratch),"TMPDIR":str(scratch),
             "XDG_CONFIG_HOME":str(scratch),"XDG_CACHE_HOME":str(scratch),
             "LANG":"C.UTF-8",
             "JAVA_TOOL_OPTIONS":"-Duser.home="+str(scratch)}
        dest=scratch/"jadx-output"
        dest.mkdir(mode=0o700)
        command=["java","-Xmx1800m","-XX:ActiveProcessorCount=2",
                 "-cp",str(JADX_JAR),"jadx.cli.JadxCLI",
                 "--no-res","--decompilation-mode","simple","-j","2",
                 "-d",str(dest),str(base)]
        did_jadx=_run(command,cwd=scratch,timeout=240,env=env,
                      logfile=scratch/"jadx.log")
        # Do not return APK source code or stdout that could contain secrets.
        source_refs=scan_jadx_sources(dest) if did_jadx else {}
        state["jadx"]={
            "status":"COMPLETED" if did_jadx else "FAILED_OR_TIMEOUT",
            **source_refs,
        }
        state["jadxExecuted"]=did_jadx
        state["status"]="PARTIAL_TOOLS_EXECUTED" if did_jadx else "TOOLS_FAILED"
        if not ghidra_ready:
            state["ghidra"]={"status":"NOT_INSTALLED_OR_VERIFIED"}
        elif not libs:
            state["ghidra"]={"status":"NO_ELF_CANDIDATES"}
        else:
            analysed=0;failed=0;functions=0;candidate_names=[]
            for i,lib in enumerate(libs):
                result=scratch/("ghidra-result-"+str(i)+".json")
                project=scratch/("ghidra-project-"+str(i))
                project.mkdir(mode=0o700)
                cmd=[str(headless),str(project),"SPDecodeQA"+str(i),
                     "-import",str(lib),"-analysisTimeoutPerFile","120",
                     "-scriptPath",str(GHIDRA_SCRIPT.parent),
                     "-postScript",GHIDRA_SCRIPT.name,str(result),
                     "-deleteProject"]
                okay=_run(cmd,cwd=scratch,timeout=180,env=env,
                          logfile=scratch/("ghidra-"+str(i)+".log"))
                if okay and result.is_file() and result.stat().st_size<4096:
                    try:
                        meta=json.loads(result.read_text("utf-8"))
                        if (isinstance(meta.get("functions"),int) and
                                0<=meta["functions"]<=10_000_000):
                            functions+=meta["functions"];analysed+=1
                            for item in meta.get("candidateFunctions",[])[:32]:
                                if (isinstance(item,dict) and
                                    re.fullmatch(r"[A-Za-z0-9_.$]{1,100}",
                                                 str(item.get("name",""))) and
                                    re.fullmatch(r"[0-9a-fA-F]{1,16}",
                                                 str(item.get("address","")))):
                                    if len(candidate_names)<48:
                                        candidate_names.append({
                                            "binary":lib.name,
                                            "name":item["name"],
                                            "address":item["address"],
                                            "evidence":"GHIDRA_SYMBOL_NAME_ONLY",
                                        })
                        else:failed+=1
                    except (OSError,ValueError,TypeError):failed+=1
                else:failed+=1
            state["ghidra"]={"status":"COMPLETED" if analysed and not failed
                             else "PARTIAL_OR_FAILED",
                             "elfAnalysed":analysed,"elfFailed":failed,
                             "functionsEnumerated":functions,
                             "candidateFunctions":candidate_names}
            state["ghidraExecuted"]=analysed>0
        return state
