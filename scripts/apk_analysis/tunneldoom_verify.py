#!/usr/bin/env python3
"""Compare complete TunnelDOOM catalogs/fields to JCA, without logging values."""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from decoders.Python.apps.TunnelDOOM_VPN import codec

# Independent list transcribed from the 13 Y0 calls in MainActivity.j1.
REFERENCE_FIELDS = (
    "ServerUser", "ServerPass", "ServerIP", "ProxyIP", "Payload", "SNI",
    "Slowchave", "Nameserver", "Slowdns", "UdpBuffer", "UdpDown", "UdpUp", "V2rayConfig",
)


def oracle(pairs):
    incoming = "".join(mode + "\t" + base64.b64encode(data).decode() + "\n" for mode, data in pairs)
    result = subprocess.run(["java", str(ROOT / "tests/golden/tunneldoom_oracle.java")],
                            input=incoming, text=True, capture_output=True, timeout=45)
    if result.returncode:
        raise ValueError("JCA oracle failed")
    return [base64.b64decode(line, validate=True) for line in result.stdout.splitlines()]


def reference(data):
    outer = oracle([("open", data)])[0].decode("utf-8")
    obj = json.loads(outer)
    fields = [(entry, key) for entry in obj["Servers"]
              for key in REFERENCE_FIELDS if key in entry and entry[key]]
    values = oracle([("field-open", entry[key].encode()) for entry, key in fields]) if fields else []
    for (entry, key), value in zip(fields, values, strict=True):
        entry[key] = value.decode("utf-8")
    return obj, len(fields), outer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("catalog", nargs="+", type=Path)
    parser.add_argument("--worker", action="store_true")
    args = parser.parse_args()
    reports = []
    for path in args.catalog:
        with path.open("rb") as stream:
            data = stream.read(codec.MAX_BYTES + 1)
        expected, fields, outer = reference(data)
        assert codec.decrypt_catalog(data) == outer
        assert codec.decode_catalog(data) == expected
        assert json.loads(codec.run(data)) == expected
        if args.worker:
            from cloud.workers.python.engine import decode_provider_catalog
            result = decode_provider_catalog("tunneldoom-vpn", data)
            assert not result["isPartial"]
            assert result["structuredJson"] == expected
            assert json.loads(result["rawText"]) == expected
        reports.append({"version": expected["Version"], "servers": len(expected["Servers"]),
                        "encryptedFields": fields, "completeParity": True, "worker": args.worker})
    print(json.dumps(reports))


if __name__ == "__main__":
    main()
