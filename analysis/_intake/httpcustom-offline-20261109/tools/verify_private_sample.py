"""Compare a private legacy export with Python, printing no configuration data."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT))
from tests.test_offline_hc_native_parity import call
from decoders.Python import HTTPCUSTOM as reference

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("sample",type=Path)
    parser.add_argument("executable")
    args=parser.parse_args()
    data=args.sample.read_bytes()
    captured=[]
    original=reference._format_top_level_json
    try:
        reference._format_top_level_json=lambda obj: captured.append(obj) or ""
        reference.HCDecryptor.execute(data)
    finally:
        reference._format_top_level_json=original
    result=call(args.executable,data)
    success=bool(captured) and result.returncode==0 and json.loads(result.stdout)==captured[0]
    print(json.dumps({"sha256":hashlib.sha256(data).hexdigest(),"size":len(data),
        "server_recognized":bool(captured),"native_exit":result.returncode,
        "complete_json_equal":success}))
    return 0 if success else 1

if __name__=="__main__":
    raise SystemExit(main())
