"""Summarize verified JADX output without exposing generated source or secrets.

Only static references inside the decompiler output are observed; names
and API calls never prove a working decoder. The parser excludes common
framework/vendor libraries to prioritize target-package candidates.
"""
from __future__ import annotations
import os
from pathlib import Path
import re

MAX_FILES=40_000
MAX_BYTES=64*1024*1024
MAX_FILE_BYTES=256*1024
MAX_HITS=48
PRUNE={"android","androidx","java","javax","kotlin","kotlinx","okio",
       "okhttp3","retrofit2"}
# Never drop all org.* or io.*: those namespaces can be the app itself.
PRUNE_SUBTREES={"org":{"apache","jetbrains","bouncycastle","json","slf4j"},
                "io":{"reactivex","netty","grpc"}}
PRUNE_COM={"google","android","squareup","facebook","microsoft"}
SIGNALS={
    "JCA_CIPHER":re.compile(r"\bCipher\.getInstance\s*\("),
    "JCA_KEY_SPEC":re.compile(r"\b(?:new\s+)?SecretKeySpec\s*\("),
    "JCA_GCM":re.compile(r"\b(?:new\s+)?GCMParameterSpec\s*\("),
    "JCA_MAC":re.compile(r"\bMac\.getInstance\s*\("),
    "JCA_DIGEST":re.compile(r"\bMessageDigest\.getInstance\s*\("),
    "JCA_PBKDF":re.compile(r"\bPBEKeySpec\s*\("),
    "JNI_LOADER":re.compile(r"\bSystem\.loadLibrary\s*\("),
    "ANDROID_BASE64":re.compile(r"\bBase64\.(?:decode|encodeToString)\s*\("),
}
METHOD=re.compile(r"(?m)^\s*(?:(?:public|private|protected|static|final|synchronized|native|abstract)\s+){0,5}(?:[\w.$<>,?\[\]]+\s+)+(?P<name>[A-Za-z_$][\w$]{0,79})\s*\(")
IGNORE_METHOD={"if","for","switch","while","return","catch","new","throw"}

def _is_framework(rel:Path):
    parts=rel.parts
    while parts and parts[0] in ("sources","src"):
        parts=parts[1:]
    if not parts:return False
    if parts[0] in PRUNE:return True
    if len(parts)>1 and parts[0] in PRUNE_SUBTREES and parts[1] in PRUNE_SUBTREES[parts[0]]:
        return True
    if len(parts)>1 and parts[0]=="com" and parts[1] in PRUNE_COM:return True
    return False

def scan_jadx_sources(output:Path)->dict:
    output=Path(output)
    root=output.resolve()
    found=[]
    signals={}
    inspected=0
    skipped=0
    total=0
    completed=True
    sites_observed=0
    for current,dirs,files in os.walk(output,topdown=True,followlinks=False):
        base=Path(current)
        rel_dir=base.relative_to(output)
        dirs[:]=[x for x in dirs if not (base/x).is_symlink()]
        if _is_framework(rel_dir):
            dirs[:]=[]
            continue
        for name in files:
            if not name.endswith(".java"):continue
            inspected+=1
            if inspected>MAX_FILES or total>MAX_BYTES:
                completed=False
                break
            path=base/name
            try:
                if path.is_symlink():skipped+=1;continue
                stat=path.stat()
                if stat.st_size>MAX_FILE_BYTES:
                    skipped+=1
                    continue
                resolved=path.resolve()
                if not resolved.is_relative_to(root):
                    skipped+=1
                    continue
                total+=stat.st_size
                if total>MAX_BYTES:completed=False;break
                source=path.read_text("utf-8","replace")
            except (OSError,ValueError):
                skipped+=1
                continue
            matches=[]
            for label,pattern in SIGNALS.items():
                for match in list(pattern.finditer(source))[:8]:
                    signals[label]=signals.get(label,0)+1
                    matches.append((match.start(),label))
            if matches:
                methods=[(m.start(),m.group("name")) for m in METHOD.finditer(source)
                         if m.group("name") not in IGNORE_METHOD]
                rel=path.relative_to(output)
                names=rel.with_suffix("").parts
                while names and names[0] in ("sources","src"):
                    names=names[1:]
                classtag=".".join(names)
                unique={}
                for pos,label in matches:
                    prior=next((m for offset,m in reversed(methods) if offset<=pos),"UNRESOLVED")
                    if pos>0 and len(prior)>80:prior="UNRESOLVED"
                    unique[(prior,label)]=True
                sites_observed+=min(len(unique),6)
                if len(found)<MAX_HITS:
                    for method,label in list(unique)[:6]:
                        if len(found)>=MAX_HITS:break
                        found.append({
                            "class":classtag[-190:],
                            "method":method,
                            "indicator":label,
                            "evidence":"JADX_DECOMPILED_SOURCE_REFERENCE",
                            "verifiedCryptoMethod":False,
                        })
        if not completed:break
    return {
        "status":"OBSERVED_PARTIAL" if not completed else "OBSERVED",
        "sourceFilesInspected":min(inspected,MAX_FILES),
        "sourceBytesInspected":min(total,MAX_BYTES),
        "skippedLargeOrUnsafe":skipped,
        "cryptoReferenceCounts":signals,
        "candidateCallSites":found,
        "candidateCallSitesObserved":sites_observed,
        "candidateCallSitesTruncated":sites_observed>len(found),
        "sourceScanBudgetComplete":completed,
        "methodValidated":False,
    }
