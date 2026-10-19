#!/usr/bin/env python3
"""C7 release evidence checker. A passing CI does NOT authorize production."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
LEDGER=ROOT/"docs/cloud/C7_EVIDENCE.json"
REQUIRED={
 "synthetic_gateway_worker","source_reference_parity_60","android_cloud_jni_apk_scan",
 "google_play_integrity_live","android_real_device_full_flow",
 "real_provider_httpinjector_cloud","real_provider_nur_catalog",
 "exporter_version_matrix","staging_https_vps","staging_load_soak",
 "security_penetration_review","privacy_release_review",
 "incident_response_rollback",
}
ALLOWED={"ci_validation_required","not_verified","verified"}

def check(data:dict,production=False)->tuple[bool,list[str]]:
    assert data.get("schemaVersion")==1 and data.get("phase")=="C7"
    rows=data.get("evaluations")
    assert isinstance(rows,list)
    identifiers=[x["id"] for x in rows]
    assert len(identifiers)==len(set(identifiers)) and set(identifiers)==REQUIRED
    assert all(x.get("status") in ALLOWED and x.get("detail") for x in rows)
    pending=[x["id"] for x in rows if x["status"]!="verified"]
    # C7 never authorizes a production release. Approval is a deliberate
    # C8 action with independent evidence review and release governance.
    if production:
        return (data.get("productionApproved") is True and not pending,pending)
    return (data.get("productionApproved") is False,pending)

def main()->int:
    parser=argparse.ArgumentParser()
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--stage",action="store_true")
    group.add_argument("--production",action="store_true")
    args=parser.parse_args()
    data=json.loads(LEDGER.read_text(encoding="utf8"))
    accepted,pending=check(data,production=args.production)
    state="ALLOWED" if accepted else "BLOCKED"
    print(f"C7 {'production' if args.production else 'staging'} gate: {state}; unresolved checks={len(pending)}")
    if pending:print("Outstanding evidence IDs: "+", ".join(pending))
    return 0 if accepted else 1
if __name__=="__main__":raise SystemExit(main())
