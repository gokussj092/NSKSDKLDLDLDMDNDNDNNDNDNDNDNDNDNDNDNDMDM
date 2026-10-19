#!/usr/bin/env python3
"""C7: generate authorized synthetic test vectors and independently run source scripts.

No real credentials are accepted; never log sample plaintext or config keys.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tests.golden.a23_generators import SYNTHETIC_GENERATORS
from tests.golden.a23_export import SUFFIX
from cloud.workers.python.engine import load_file_engines,_child_env

# Diverse original runtimes and envelope variants; no real vendor files.
CASES=("ev2ray-plain","httptweak-v1-ht","ssc-chacha20")

def vectors() -> dict:
    catalog=load_file_engines()
    manifest=json.loads((ROOT/"tests/golden/manifest.json").read_text("utf8"))
    allowed={item["id"]:item for item in manifest["fixtureCaseDefinitions"] if item["sourceKind"]=="synthetic"}
    result=[]
    for name in CASES:
        entry=allowed[name]
        suffix=SUFFIX[name]
        engine=catalog[suffix]
        data=SYNTHETIC_GENERATORS[name]()
        digest=hashlib.sha256(data).hexdigest()
        if digest!=entry["inputSha256"]:
            raise RuntimeError("C7_SYNTHETIC_INPUT_DRIFT:"+name)
        runtime=sys.executable if engine["runtime"]=="python" else shutil.which(engine["runtime"])
        if not runtime:
            raise RuntimeError("C7_ENGINE_RUNTIME_MISSING:"+name)
        with tempfile.TemporaryDirectory(prefix="c7-ref-") as folder:
            p=Path(folder)/("input."+suffix)
            p.write_bytes(data)
            direct=subprocess.run([runtime,engine["source"],str(p)],cwd=ROOT,
                env=_child_env(folder),input=None,stdin=subprocess.DEVNULL,
                capture_output=True,timeout=20,check=False)
        if direct.returncode or not direct.stdout:
            raise RuntimeError("C7_REFERENCE_SOURCE_FAILED:"+name)
        text=direct.stdout.decode("utf8")
        result.append({"id":name,"format":suffix,
            "dataBase64":base64.b64encode(data).decode("ascii"),
            "rawText":text,
            "inputSha256":digest,
            "referenceSha256":hashlib.sha256(direct.stdout).hexdigest()})
    # C2 protected-format reference cases: synthetic only; all secrets are fake.
    from tests.golden.hc_sip_new_variants import S4_SYNTHETIC_PASSWORD, hccfg_file
    from tests.test_nur_tunnel_solid import CATALOG
    from scripts.android_g_text_fixtures import build
    from cloud.workers.python.engine import decode_file, decode_catalog, decode_text
    password_encrypted=hccfg_file(password=S4_SYNTHETIC_PASSWORD)
    hc=decode_file("hc",password_encrypted,
                   credentials={"password":S4_SYNTHETIC_PASSWORD})
    text_case=next(row for row in build()["vectors"]
                   if row["scheme"]=="falcontunnel://import/")
    text_result=decode_text(text_case["input"])
    catalog_data=CATALOG.encode("ascii")
    catalog_result=decode_catalog(catalog_data)
    extras={
        "hc":{"dataBase64":base64.b64encode(password_encrypted).decode("ascii"),
              "credentials":{"password":S4_SYNTHETIC_PASSWORD},
              "rawText":hc["rawText"],"structuredJson":hc["structuredJson"]},
        "text":{"input":text_case["input"],"rawText":text_result["rawText"],
                "structuredJson":text_result["structuredJson"]},
        "catalog":{"dataBase64":base64.b64encode(catalog_data).decode("ascii"),
                   "rawText":catalog_result["rawText"],
                   "structuredJson":catalog_result["structuredJson"]},
    }
    return {"license":"synthetic-test-input-only","cases":result,"extras":extras}

if __name__=="__main__":
    print(json.dumps(vectors(),ensure_ascii=False,separators=(",",":")))
