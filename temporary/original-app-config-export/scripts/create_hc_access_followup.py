#!/usr/bin/env python3
"""Two private follow-up HCX4 files using the native enum value 'none'."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

from hc_hcx4_n11_experiment import rewrap, private_write, codec, hc
from lossless_json import differences, equal, parse
from create_hc_import_matrix import NOTE, URL

CASES = ("D_access_none", "E_combined_none")


def generate_followup(raw):
    original = codec.decrypt(raw)
    env = codec.open_envelope(raw)
    key, aad = codec.derive(env, None, None)
    outputs, records = [], []
    for index, case in enumerate(CASES):
        candidate = copy.deepcopy(original)
        candidate["main"]["g"]["a"] = "none"
        if index == 1:
            candidate["main"]["g"]["v"], candidate["main"]["u"] = NOTE, URL
        candidate["protections"] = hc._norm_prot(candidate["main"]["g"])
        output = rewrap(raw, candidate)
        new_env = codec.open_envelope(output)
        # Check the independent pure-Python AEAD as well as the codec.
        from audit_hc_matrix import authenticate_pure

        _, clear, tags = authenticate_pure(output)
        if not equal(parse(clear), candidate["main"]):
            raise AssertionError("Authenticated main differs from the intended edit")
        if not equal(env["j"], new_env["j"]):
            raise AssertionError("Profile or sidecar changed")
        if not isinstance(candidate["main"]["g"]["a"], str):
            raise AssertionError("Access mode type changed")
        # Includes expiry and all unedited protection flags, with exact types.
        old_g, new_g = copy.deepcopy(original["main"]["g"]), copy.deepcopy(
            candidate["main"]["g"]
        )
        for obj in (old_g, new_g):
            del obj["a"]
            if index == 1:
                del obj["v"]
        if not equal(old_g, new_g):
            raise AssertionError("Unedited restrictions changed")
        paths = differences(original["main"], candidate["main"])
        records.append(
            dict(
                case=case,
                sha256=hashlib.sha256(output).hexdigest(),
                bytes=len(output),
                access_mode="none",
                access_mode_type="str",
                changed_paths=["main." + ".".join(p) for p in paths],
                local_crypto_roundtrip=True,
                pure_python_tags_verified=tags,
                original_profiles_and_sidecars_preserved=True,
                unedited_restrictions_preserved=True,
                vendor_import_result="PENDING_MANUAL_TEST",
                editability_result="PENDING_MANUAL_TEST",
            )
        )
        outputs.append(output)
    return outputs, records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument(
        "--output-dir", required=True, type=Path, help="Must be a NEW directory"
    )
    args = parser.parse_args()
    raw = args.source.read_bytes()
    outputs, records = generate_followup(raw)
    args.output_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    for case, output in zip(CASES, outputs):
        private_write(args.output_dir / (case + ".hc"), output)
    manifest = dict(
        source_sha256=hashlib.sha256(raw).hexdigest(),
        source_bytes=len(raw),
        purpose="Replace rejected boolean with native NONE enum; Android follow-up pending",
        cases=records,
    )
    private_write(
        args.output_dir / "import_matrix.json",
        (json.dumps(manifest, indent=2) + "\n").encode(),
    )
    print(
        "Generated D_access_none and E_combined_none. All local AEAD tags pass. Android import/editability pending."
    )


if __name__ == "__main__":
    main()
