#!/usr/bin/env python3
"""Compare complete Aura documents with libsodium/JDK and isolated workers.

Prints only counts; accepts private local files, never caller-supplied URLs.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tests.golden import aura_net_reference as reference
from mm_tunnel_verify import independent_document
from decoders.Python.apps.Aura_Net_VPN import codec, file_decoder


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", action="append", type=Path, default=[])
    parser.add_argument("--file", type=Path)
    parser.add_argument("--worker", action="store_true")
    args = parser.parse_args()
    cases = [(v["kind"], v["wire"].encode(), v["expected"]) for v in json.loads(
        (ROOT/"tests/golden/aura_net_vectors.json").read_text())["documents"]]
    cases.extend(("catalog", path.read_bytes(), None) for path in args.catalog)
    if args.file:
        cases.append(("file", args.file.read_bytes(), None))
    total_fields = 0
    summaries = []
    for kind, wire, golden in cases:
        expected, fields = independent_document(reference, wire)
        total_fields += fields
        if golden is not None and expected != golden:
            raise ValueError("Independent golden document mismatch")
        full = {"application": "Aura Net VPN", "extension": ".aura", "config": expected} if kind == "file" else expected
        if args.worker:
            from cloud.workers.python.engine import decode_file, decode_provider_catalog
            result = decode_file("aura", wire) if kind == "file" else decode_provider_catalog("aura-net-vpn", wire)
            if result["isPartial"] or json.loads(result["rawText"]) != full:
                raise ValueError("Incomplete worker output")
            actual = result["structuredJson"]
        else:
            actual = json.loads(file_decoder.run(wire)) if kind == "file" else codec.decode_catalog(wire)
        if actual != full:
            raise ValueError("Complete JSON differs from independent reference")
        if golden is None and kind == "catalog":
            summaries.append({"version": expected["Version"], "servers": len(expected["Servers"]),
                              "networks": len(expected["Networks"]), "encryptedFields": fields})
    print(json.dumps({"completeIndependentDocuments": len(cases), "innerFields": total_fields,
                      "isolatedWorker": args.worker, "privateCatalogs": summaries, "privateFile": bool(args.file)}))


if __name__ == "__main__":
    main()
