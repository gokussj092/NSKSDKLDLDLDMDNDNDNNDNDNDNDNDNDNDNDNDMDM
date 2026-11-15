#!/usr/bin/env python3
"""One authorized fixed-origin request; retain only counts and hashes as proof."""
import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT))
from decoders.Python.apps.DTunnel_Mod import DTunnel as codec
from cloud.workers.python.engine import decode_provider_catalog


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    proof={"observed_at":datetime.now(timezone.utc).isoformat(),
           "credential_source":"owner-supplied authorized script default",
           "credential_value_recorded":False,"status":"FAILED"}
    original=codec.build_opener
    class RecordingOpener:
        def __init__(self,opener):self.opener=opener
        def open(self,*a,**kw):
            try:
                response=self.opener.open(*a,**kw)
            except Exception as exc:
                if isinstance(getattr(exc,"code",None),int):proof["http_status"]=exc.code
                raise
            proof["http_status"]=response.status
            return response
    try:
        with patch.object(codec,"build_opener",lambda *a,**kw:RecordingOpener(original(*a,**kw))):
            raw=codec.fetch_catalog(codec.CATALOG_URL)
        expected=codec.decode_catalog(raw)
        result=decode_provider_catalog("dtunnel-mod",raw)
        digest=lambda obj:hashlib.sha256(json.dumps(obj,ensure_ascii=False,sort_keys=True).encode()).hexdigest()
        if digest(expected)!=digest(result["structuredJson"]):raise ValueError("worker mismatch")
        proof.update(status="VERIFIED_REAL",response_bytes=len(raw),
                     ciphertext_sha256=hashlib.sha256(raw).hexdigest(),profiles=len(expected),
                     complete_worker_match=True,fields_truncated=False)
    except Exception as exc:
        proof["error_code"]=getattr(exc,"code",type(exc).__name__)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(proof,indent=2)+"\n")
    print(json.dumps(proof))
    return 0 if proof["status"]=="VERIFIED_REAL" else 1


if __name__=="__main__":raise SystemExit(main())
