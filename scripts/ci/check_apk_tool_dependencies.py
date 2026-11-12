#!/usr/bin/env python3
"""F7-A0-P01: offline dependency metadata contract, no APK tools executed."""
from __future__ import annotations
import argparse, json, re, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
PIN=re.compile(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)")
SHA=re.compile(r"[0-9a-f]{64}")
def norm(s): return re.sub(r"[-_.]+","-",s).lower()
def check(root=ROOT):
    reg=json.loads((root/"analysis/platform/apk-tooling/dependencies.v1.json").read_text("utf-8"))
    req=[s.strip() for s in (root/"scripts/apk_analysis/requirements.txt").read_text("utf-8").splitlines() if s.strip() and not s.strip().startswith("#")]
    pins={}
    for line in req:
        m=PIN.fullmatch(line)
        if not m: raise ValueError("Unpinned requirement: "+line)
        key=norm(m[1])
        if key in pins: raise ValueError("Duplicate requirement: "+key)
        pins[key]=m[2]
    found=set()
    for p in reg["packages"]:
        key=norm(p["name"])
        if key not in pins or key in found: raise ValueError("Unexpected or duplicate registry entry: "+key)
        found.add(key)
        if pins[key]!=str(p.get("version")) or p.get("requirement") not in req: raise ValueError("Dependency pin mismatch: "+key)
        if p.get("unattended_execution")!="DISABLED": raise ValueError("Not allowed to authorize automatic execution: "+key)
        sd=p.get("source_distribution",{})
        if not SHA.fullmatch(str(sd.get("sha256_reported_by_pypi",""))): raise ValueError("Bad source hash: "+key)
        if sd.get("checksum_scope")!="REFERENCE_SDIST_NOT_INSTALLED_WHEEL": raise ValueError("Incorrect checksum scope: "+key)
        if not sd.get("filename","").lower().endswith("-"+pins[key]+".tar.gz"): raise ValueError("Artifact version mismatch: "+key)
        if not str(p.get("license_evidence_url","")).startswith("https://pypi.org/project/"): raise ValueError("No upstream metadata source: "+key)
    if set(pins)!=found: raise ValueError("Missing registry entries")
    audit=reg["p01_review"]
    if audit.get("installed_artifact_hash_count")!=0 or audit.get("automated_worker_approval") is not False:
        raise ValueError("Unverified binary or execution approval")
    return {"pinned":len(found),"reference_sdists":len(found),"installed_wheels_attested":0,"execution":"NOT_APPROVED"}
if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--repo-root",type=Path,default=ROOT)
    args=parser.parse_args()
    try: print(json.dumps(check(args.repo_root),sort_keys=True))
    except (ValueError,OSError,KeyError) as exc:
        print("F7-A0-P01: "+str(exc),file=sys.stderr)
        sys.exit(1)
