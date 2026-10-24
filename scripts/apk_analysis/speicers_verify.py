#!/usr/bin/env python3
"""Compare complete private catalogs with independent JDK and offline worker."""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from decoders.Python.apps.Speicers_Pro_VPN import server_catalog_decoder as codec
from cloud.workers.python.catalog_vpn_bridge import decode


def verify(path):
    source = codec._read(path)
    actual = codec.decode_catalog(source)
    oracle = ROOT / "tests/golden/speicers_oracle.java"
    reference = json.loads(subprocess.run(["java", str(oracle), "outer", str(path)], check=True, capture_output=True, timeout=45).stdout)
    fields = []
    if "Servers" in reference:
        for item in reference["Servers"]:
            for key in codec.FIELD_NAMES.values():
                if key in item:
                    fields.append((item, key, item[key]))
    if fields:
        result = subprocess.run(["java", str(oracle), "fields"],
            input=("\n".join(v for _, _, v in fields)+"\n").encode(),
            check=True, capture_output=True, timeout=45)
        values = result.stdout.decode().splitlines()
        assert len(fields) == len(values), "Oracle omitted fields"
        for (item, key, _), value in zip(fields, values):
            item[key] = base64.b64decode(value, validate=True).decode("utf-8")
    assert actual == reference, "Complete JDK document differs"
    assert actual == json.loads(decode("speicers-pro-vpn", source)), "Complete worker document differs"
    return {"version": actual.get("Version", actual.get("version")),
            "records": len(actual.get("Servers", actual.get("servers", []))),
            "fields": len(fields), "jdkEqual": True, "workerEqual": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("catalogs", type=Path, nargs="+")
    args = parser.parse_args()
    for path in args.catalogs:
        print(json.dumps(verify(path)))


if __name__ == "__main__":
    main()
