#!/usr/bin/env python3
"""Verify fixed codec bindings/imports offline; never claim a live catalog test."""
import hashlib
import json
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[5]
sys.path.insert(0,str(ROOT))
from cloud.workers.python.supplied_bridge import BY_ID,load,offline


def verify(provider):
    item=BY_ID[provider]
    with offline():
        module=load(item)
        assert any(callable(getattr(module,name,None)) for name in
                   ("decode","decode_json_bytes","decode_blob_text","run"))
        if item["fileModule"]:
            load(item,"fileModule")
    source=ROOT/"decoders/Python/apps"/item["appDir"]/item["catalogModule"]
    return {"provider":provider,"codec_import":"PASS",
            "sha256":hashlib.sha256(source.read_bytes()).hexdigest(),
            "remote_validated_by_this_check":False}


if __name__=="__main__":
    selected=sorted(BY_ID) if sys.argv[1:]==["--all"] else sys.argv[1:]
    if not selected:raise SystemExit("Use --all or an allowlisted provider ID")
    print(json.dumps([verify(provider) for provider in selected]))
