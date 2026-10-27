#!/usr/bin/env python3
"""Report structural HC899 differences without exposing connection values."""

import argparse
import hashlib
import json
from pathlib import Path

from hc_open_layout_experiment import validate_file, unpack_profile, codec
from audit_hc_matrix import authenticate_pure
from hc_hcx4_n11_experiment import private_write


def summarize(raw):
    env, decoded = validate_file(raw)
    key, aad = codec.derive(env, None, None)
    profiles = []
    for section in env["j"]:
        binary, wrapped, sidecar = unpack_profile(section, key, aad)
        profile = codec.parse_profile(binary, section["a"])
        profiles.append(
            dict(
                authenticated_section_payload="HPR1" if wrapped else "HPC1",
                decrypted_profile_payload="HPC1",
                encrypted_sidecar_present=sidecar is not None,
                customPayload_option_present="customPayload" in profile["options"],
                customPayload_option_empty=profile["options"].get("customPayload")
                == "",
                profile_auxiliary_string_empty=profile["payload"] == "",
            )
        )
    return dict(
        sha256=hashlib.sha256(raw).hexdigest(),
        bytes=len(raw),
        build=env["n"],
        schema=env["b"],
        schedule=env["e"],
        access_mode=decoded["main"]["g"]["a"],
        features=env["f"],
        main_capabilities=decoded["main"]["c"],
        main_fields={k: type(v).__name__ for k, v in decoded["main"].items()},
        protection_fields={
            k: type(v).__name__ for k, v in decoded["main"]["g"].items()
        },
        profiles=profiles,
        authenticated_aead_tags=authenticate_pure(raw)[2],
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--reference", required=True, type=Path)
    parser.add_argument("--previous-none", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = {
        name: summarize(path.read_bytes())
        for name, path in [
            ("locked_source", args.source),
            ("owned_open_reference", args.reference),
            ("rejected_mode_only_none", args.previous_none),
        ]
    }
    report["interpretation"] = {
        "none_string_confirmed_in_owner_export": True,
        "mode_only_none_conversion_rejected_by_owner": True,
        "structural_difference_confirmed": True,
        "specific_importer_failure_mechanism_proven": False,
        "new_open_layout_import_status": "PENDING_MANUAL_TEST",
        "reference_note_style_and_label_fields_not_assumed_required": True,
    }
    private_write(args.output, (json.dumps(report, indent=2) + "\n").encode())
    print(
        "Compared authenticated layouts; only schema, types, framing and file hashes were recorded."
    )


if __name__ == "__main__":
    main()
