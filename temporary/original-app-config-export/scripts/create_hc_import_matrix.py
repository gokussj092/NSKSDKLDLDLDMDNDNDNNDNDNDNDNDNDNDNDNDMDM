#!/usr/bin/env python3
"""TEMPORARY — create five isolated authenticated HCX4 samples for manual app import."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

from decoders.Python.apps.HTTP_Custom import codec
from hc_hcx4_n11_experiment import rewrap


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--edited", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    raw = args.source.read_bytes()
    original = codec.decrypt(raw)
    desired = json.loads(args.edited.read_text("utf-8"))
    directory = args.output_dir.resolve()
    if directory == args.source.parent.resolve():
        parser.error("Output directory must be outside the source fixture directory")
    directory.mkdir(parents=True, exist_ok=True)
    original_g = original["main"]["g"]
    edited_g = desired["main"]["g"]
    cases = ("baseline_rewrap", "note_only", "url_only", "access_only", "combined")
    results = []
    for case in cases:
        candidate = copy.deepcopy(original)
        if case in ("note_only", "combined"):
            candidate["main"]["g"]["v"] = edited_g["v"]
            candidate["protections"]["note"] = edited_g["v"]
        if case in ("url_only", "combined"):
            candidate["main"]["u"] = desired["main"]["u"]
        if case in ("access_only", "combined"):
            candidate["main"]["g"]["a"] = edited_g["a"]
            candidate["protections"]["accessMode"] = edited_g["a"]
        if case != "baseline_rewrap":
            assert candidate["main"]["g"].get("c") == original_g.get("c")
        output = directory / (case + ".hc")
        if output.exists():
            parser.error("Refusing to overwrite: " + str(output))
        cipher = rewrap(raw, candidate)
        output.write_bytes(cipher)
        results.append({
            "case":case, "sha256":hashlib.sha256(cipher).hexdigest(),
            "bytes":len(cipher), "local_crypto_roundtrip":True,
            "vendor_import_result":"PENDING_MANUAL_TEST"
        })
    record = directory / "import_matrix.json"
    if record.exists():
        parser.error("Refusing to overwrite: " + str(record))
    record.write_text(json.dumps(results, indent=2) + "\n", "utf-8")
    print("Generated 5 local authenticated experiments. Vendor import: NOT TESTED.")


if __name__ == "__main__":
    main()
