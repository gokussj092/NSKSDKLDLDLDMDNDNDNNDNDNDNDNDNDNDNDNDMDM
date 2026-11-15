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
import time
from .qa_full_profile import full_profile, remaining_seconds
from .qa_method_recipes import merge_recipe_reports
import zipfile
from .qa_jadx_refs import scan_jadx_sources
from .qa_jadx_recovery import DEX_NAME, diagnose_termination, recover_jadx
from .qa_tool_rpc import inspect_remote

JADX_JAR=Path("/opt/spdecode/scripts/apk_analysis/cache/jadx-1.5.6-all.jar")
JADX_SHA256="fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b"
MAX_TOOL_APK=100*1000*1000
MAX_GHIDRA_LIBS=3
MAX_NATIVE_REPORT=256_000
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


def _run_jadx(command:list[str],*,cwd:Path,timeout:int,env:dict,logfile:Path)->str:
    """Minimal non-sensitive termination classification; never return logs."""
    with logfile.open("wb") as log:
        try:
            child=subprocess.Popen(command,cwd=cwd,env=env,
                stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                start_new_session=True)
        except OSError:
            return "START_FAILED"
        try:
            return "EXIT_ZERO" if child.wait(timeout=timeout)==0 else "EXIT_NONZERO"
        except subprocess.TimeoutExpired:
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            try:child.wait(timeout=10)
            except subprocess.TimeoutExpired:pass
            return "TIMEOUT"


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


def _base_and_libs(source:Path,dest:Path,*,lite:bool=False,profile:dict|None=None):
    """Extract one base APK and profile-bounded ELF candidates."""
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
                if lite or len(splits)>=8:break
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
    native_limit=profile["nativeLibraries"] if profile else MAX_GHIDRA_LIBS
    native_bytes=profile["nativeBytes"] if profile else 32*1024*1024
    binaries=[]
    total_native=0;oversized_native=0
    def priority(item):
        name=item.filename.rsplit("/",1)[-1].lower()
        system=any(k in name for k in ("conscrypt","datastore","c++_shared",
                                        "firebase","sqlite","crashlytics"))
        domain=any(k in name for k in ("vpn","hysteria","tun","tunnel",
                                        "config","crypto","tls"))
        return (1 if system else 0,0 if domain else 1,-item.file_size)
    for split in splits:
        with zipfile.ZipFile(split) as archive:
            all_native=[entry for entry in archive.infolist() if
                entry.filename.startswith("lib/") and
                entry.filename.endswith(".so")]
            total_native+=len(all_native)
            candidates=sorted((entry for entry in all_native if
                52<=entry.file_size<=native_bytes),key=priority)
            oversized_native+=len(all_native)-len(candidates)
            for info in candidates:
                if lite or len(binaries)>=native_limit:break
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
    return base,binaries,total_native,oversized_native


def _prefer_dex_first(base:Path, lite:bool)->bool:
    """Inspect the actual base archive rather than an optional upstream report.

    The isolated RPC worker deliberately supplies an empty DEX inventory. This
    bounded ZIP-directory check prevents monolithic JADX heap exhaustion there.
    No DEX bytes are decompressed or executed during this preflight.
    """
    if not lite:
        return False
    with zipfile.ZipFile(base) as archive:
        dex=[item for item in archive.infolist()
             if DEX_NAME.fullmatch(item.filename) and not item.is_dir()]
    return len(dex)>=2 and sum(item.file_size for item in dex)>=16*1024*1024


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
    lite=os.environ.get("SPDECODE_APK_QA_LITE")=="true"
    if _memory_limit()<(1024*1024*1024 if lite else MIN_MEMORY):
        state["status"]="INSUFFICIENT_CONTAINER_MEMORY"
        return state
    profile=None if lite else full_profile(_memory_limit())
    deadline=time.monotonic()+(profile["jobSeconds"] if profile else 900)
    jadx_deadline=time.monotonic()+(profile["jadxSeconds"] if profile else 660)
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
    ghidra_ready=(not lite and bool(re.fullmatch(r"[a-f0-9]{64}",expected)) and
                  os.environ.get("SPDECODE_APK_QA_GHIDRA")=="enabled" and
                  home.is_dir() and not home.is_symlink() and
                  headless.is_file() and not headless.is_symlink() and
                  GHIDRA_SCRIPT.is_file() and
                  hashlib.sha256(headless.read_bytes()).hexdigest()==expected)
    with tempfile.TemporaryDirectory(prefix=".apkqa-tools-",dir=source.parent) as td:
        scratch=Path(td)
        base,libs,total_native,oversized_native=_base_and_libs(source,scratch,lite=lite,profile=profile)
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
        command=["java","-Xmx512m" if lite else "-Xmx"+profile["heap"],
                 "-XX:ActiveProcessorCount=1" if lite else "-XX:ActiveProcessorCount="+str(profile["threads"]),
                 "-cp",str(JADX_JAR),"jadx.cli.JadxCLI",
                 "--no-res","--decompilation-mode","simple" if lite else "auto",
                 "-j","1" if lite else str(profile["threads"]),
                 "-d",str(dest),str(base)]
        # Large multidex applications exhaust a small JVM on the monolithic pass.
        # Prefer bounded per-DEX work immediately, keeping the real output of
        # ordinary/smaller APKs unchanged.
        # The remote worker calls inspect_tooling(source, {}) and therefore
        # must determine this strategy from the validated base APK itself.
        large_dex=_prefer_dex_first(base,lite)
        termination=("DEX_FIRST_RESOURCE_BUDGET" if large_dex else
                     _run_jadx(command,cwd=scratch,timeout=180 if lite else profile["primarySeconds"],env=env,
                               logfile=scratch/"jadx.log"))
        did_jadx=termination=="EXIT_ZERO"
        # Do not return APK source code or stdout that could contain secrets.
        # Preserve genuine partial source evidence on timeout/OOM, but do not
        # claim the Java decompiler completed when its process failed.
        source_refs=scan_jadx_sources(dest)
        primary_files=source_refs.get("sourceFilesInspected",0)
        recovery={"status":"NOT_REQUIRED","attempts":[],"dexRecovered":0}
        if not did_jadx:
            # Keep the first, possibly useful, JADX output and retry only
            # independently extracted DEX files in a fixed sequential budget.
            try:
                recovery=recover_jadx(base,scratch,JADX_JAR,env,_run_jadx,scan_jadx_sources,
                    **({} if lite else {"profile":profile,"deadline":jadx_deadline}))
            except (OSError,ValueError,RuntimeError,zipfile.BadZipFile):
                # The primary attempt may already contain valuable sources.
                # A broken retry must not erase the primary evidence.
                recovery={"status":"RECOVERY_FAILED","attempts":[],"dexRecovered":0,
                          "sourceFilesInspected":0,"sourceBytesInspected":0,
                          "candidateCallSites":[],"cryptoReferenceCounts":{}}
            source_refs["sourceFilesInspected"]=(
                primary_files+recovery["sourceFilesInspected"])
            source_refs["sourceBytesInspected"]=(
                source_refs.get("sourceBytesInspected",0)+
                recovery["sourceBytesInspected"])
            # Preserve the true per-attempt observation count while exporting
            # only distinct bounded class/method/API indicators.
            primary_sites=source_refs.get("candidateCallSites",[])
            combined=primary_sites+recovery["candidateCallSites"]
            distinct=[]
            seen=set()
            for site in combined:
                key=(site.get("class"),site.get("method"),site.get("indicator"))
                if key not in seen:
                    seen.add(key)
                    distinct.append(site)
            source_refs["candidateCallSites"]=distinct[:48]
            observed=(source_refs.get("candidateCallSitesObserved",len(primary_sites))+
                      recovery.get("candidateCallSitesObserved",
                                   len(recovery["candidateCallSites"])))
            source_refs["candidateCallSitesObserved"]=observed
            source_refs["candidateCallSitesTruncated"]=(observed>len(distinct[:48]))
            source_refs["methodRecipes"]=merge_recipe_reports([
                source_refs.get("methodRecipes",{}),recovery.pop("methodRecipes",{})])
            counts=source_refs.setdefault("cryptoReferenceCounts",{})
            for label,value in recovery["cryptoReferenceCounts"].items():
                counts[label]=counts.get(label,0)+value
        partial=not did_jadx and source_refs.get("sourceFilesInspected",0)>0
        reference_status=source_refs.pop("status","UNKNOWN")
        state["jadx"]={
            **source_refs,
            "referenceScanStatus":reference_status,
            "status":"COMPLETED" if did_jadx else
                     ("PARTIAL_OUTPUT" if partial else "FAILED"),
            "terminationReason":termination,
            "failureCategory":("MONOLITHIC_SKIPPED_FOR_DEX" if large_dex else
                diagnose_termination(scratch/"jadx.log",termination)),
            "recovery":recovery,
            "sourceReferencesMayOverlapRetries":not did_jadx,
            "decompilationMode":"simple" if lite else "auto",
            "attempted":True,
            "completed":did_jadx,
        }
        state["jadxAttempted"]=True
        state["jadxExecuted"]=did_jadx
        state["resourceProfile"]="JADX_LITE" if lite else profile["name"]
        state["toolDistribution"]="JADX_LITE" if lite else "JADX_FULL"
        if profile:
            state["resourceBudget"]={key:profile[key] for key in (
                "heap","threads","jobSeconds","jadxSeconds","nativeLibraries")}
        state["uploadedCodeExecuted"]=False
        state["status"]=(
            "PARTIAL_TOOLS_EXECUTED" if did_jadx
            else ("TOOLS_PARTIAL" if partial else "TOOLS_FAILED")
        )
        if not ghidra_ready:
            state["ghidra"]={"status":"DISABLED_IN_LITE_PROFILE" if lite else "NOT_INSTALLED_OR_VERIFIED",
                             "elfDiscovered":total_native}
        elif not libs:
            state["ghidra"]={"status":"NO_ELF_CANDIDATES",
                             "elfDiscovered":total_native,
                             "elfOversized":oversized_native}
        else:
            analysed=0;failed=0;functions=0;candidate_names=[]
            budget_skipped=0
            for i,lib in enumerate(libs):
                seconds=remaining_seconds(deadline,time.monotonic(),profile["ghidraProcessSeconds"])
                if seconds<1:
                    budget_skipped=len(libs)-i
                    break
                result=scratch/("ghidra-result-"+str(i)+".json")
                project=scratch/("ghidra-project-"+str(i))
                project.mkdir(mode=0o700)
                cmd=[str(headless),str(project),"SPDecodeQA"+str(i),
                     "-import",str(lib),"-analysisTimeoutPerFile",str(profile["ghidraAnalysisSeconds"]),
                     "-scriptPath",str(GHIDRA_SCRIPT.parent),
                     "-postScript",GHIDRA_SCRIPT.name,str(result),
                     "-deleteProject"]
                okay=_run(cmd,cwd=scratch,timeout=seconds,env=env,
                          logfile=scratch/("ghidra-"+str(i)+".log"))
                if result.is_file() and result.stat().st_size<=MAX_NATIVE_REPORT:
                    try:
                        meta=json.loads(result.read_text("utf-8"))
                        if (isinstance(meta.get("functions"),int) and
                                0<=meta["functions"]<=10_000_000):
                            functions+=meta["functions"];analysed+=1
                            if not okay:failed+=1
                            for item in meta.get("candidateFunctions",[])[:32]:
                                if (isinstance(item,dict) and
                                    re.fullmatch(r"[A-Za-z0-9_.$]{1,160}",
                                                 str(item.get("name",""))) and
                                    re.fullmatch(r"[0-9a-fA-F]{1,16}",
                                                 str(item.get("address","")))):
                                    if len(candidate_names)<48:
                                        candidate_names.append({
                                            "binary":lib.name,
                                            "name":item["name"],
                                            "address":item["address"],
                                            "evidence":"GHIDRA_STATIC_FUNCTION_EVIDENCE",
                                            "decompilationCompleted":item.get("decompilationCompleted") is True,
                                            **({"decompiledCSha256":item["decompiledCSha256"]}
                                               if re.fullmatch(r"[0-9a-f]{64}",str(item.get("decompiledCSha256",""))) else {}),
                                            **({"decompiledCLines":item["decompiledCLines"]}
                                               if type(item.get("decompiledCLines")) is int and 0<item["decompiledCLines"]<=10_000_000 else {}),
                                            "calledCryptoFunctions":[name for name in item.get("calledCryptoFunctions",[])[:16]
                                                if isinstance(name,str) and re.fullmatch(r"[A-Za-z0-9_.$]{1,160}",name)],
                                            "methodValidated":False,
                                        })
                        else:failed+=1
                    except (OSError,ValueError,TypeError):failed+=1
                else:failed+=1
            fully_covered=analysed==total_native and not failed and not budget_skipped
            state["ghidra"]={
                "status":("COMPLETED" if fully_covered else
                          "PARTIAL_LIMITED" if analysed else "FAILED_OR_TIMEOUT"),
                "elfDiscovered":total_native,
                "elfSelected":len(libs),
                "elfSkipped":max(0,total_native-len(libs)),
                "elfOversized":oversized_native,
                "elfBudgetSkipped":budget_skipped,
                "nativeMethodsDecompiled":sum(x.get("decompilationCompleted",False) for x in candidate_names),
                "elfAnalysed":analysed,"elfFailed":failed,
                "functionsEnumerated":functions,
                "candidateFunctions":candidate_names,
            }
            state["ghidraExecuted"]=analysed>0
        return state
