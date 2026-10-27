#!/usr/bin/env python3
"""Reference-backed HC899 open-layout experiments; not a production exporter."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import struct
from pathlib import Path

from hc_hcx4_n11_experiment import codec, hc, open_original, seal, private_write, rewrap
from lossless_json import parse, replace_values, equal, differences
from create_hc_import_matrix import NOTE, URL
from audit_hc_matrix import authenticate_pure


def validate_file(raw):
    decoded = codec.decrypt(raw)  # Authenticate every supported layer first.
    env = codec.open_envelope(raw)
    if (
        type(env.get("b")) is not int
        or env["b"] != 10
        or env.get("n") != 899
        or (env.get("c"), env.get("d"), env.get("e")) != ("s1", "h1", "n11")
        or bool(env.get("h"))
    ):
        raise ValueError(
            "Only authenticated unprotected HCX4/HCCFG10/n11/899 is supported"
        )
    if not equal(decoded["main"].get("c"), env.get("f")):
        raise ValueError("Observed main/envelope capability lists are inconsistent")
    return env, decoded


def unpack_profile(section, key, aad):
    clear = hc._dec_section(section, key, aad)
    wrapped = clear.startswith(b"HPR1")
    if wrapped:
        clear = hc._xdec(
            key, clear[4:28], aad + b"\0" + section["a"].encode() + b":r", clear[28:]
        )
    if not clear.startswith(b"HPC1"):
        raise ValueError("Unknown profile grammar; refusing layout conversion")
    codec.parse_profile(clear, section["a"])
    return clear, wrapped, hc._dec_sidecar(section, key, aad)


def options_span(profile):
    reader = hc._R(profile)
    if reader.take(4) != b"HPC1" or reader.u32() != 11:
        raise ValueError("Unknown HPC1 layout")
    for _ in range(3):
        reader.txt()
    reader.u32()
    for _ in range(
        3
    ):  # username, password, auxiliary string (decoder calls it payload)
        reader.txt()
    start = reader.o
    options = reader.txt().encode("utf-8")
    end = reader.o
    return start, end, options


def migrate_payload(profile, sidecar):
    """Move authenticated custom HTTP payload into its existing HPC1 option.

    Keep all other binary fields and JSON tokens exactly. Never guess which
    field a sidecar represents, or replace a different non-empty payload.
    """
    if sidecar is None:
        return profile, False
    text = sidecar.decode("utf-8")
    start, end, raw_options = options_span(profile)
    options = parse(raw_options)
    if not isinstance(options, dict) or "customPayload" not in options:
        raise ValueError("No observed customPayload option for sidecar migration")
    old = options["customPayload"]
    if not isinstance(old, str) or old not in ("", text):
        raise ValueError("Conflicting custom payload; refusing data loss")
    new = replace_values(raw_options, {("customPayload",): text})
    result = profile[:start] + struct.pack(">I", len(new)) + new + profile[end:]
    if (
        result[:start] != profile[:start]
        or result[start + 4 + len(new) :] != profile[end:]
    ):
        raise AssertionError("Unedited HPC1 bytes changed")
    return result, True


def connection_view(decoded):
    """Canonical comparison only; never log or write this private view."""
    result = copy.deepcopy(decoded["config"])
    for profile in result:
        options = profile.get("options")
        if not isinstance(options, dict):
            raise ValueError("Unsupported options grammar")
        sidecar = profile.pop("custom_payload_sidecar", None)
        if "custom_payload_sidecar_hex" in profile:
            raise ValueError("Binary sidecar semantics not established")
        explicit = options.get("customPayload", "")
        if sidecar is not None:
            if explicit not in ("", sidecar):
                raise ValueError("Conflicting effective custom payload")
            options["customPayload"] = sidecar
        profile.pop("options_text", None)
    return result


def convert(raw, reference, *, combined=False, add_profiles=True, relocate=True):
    env, original = validate_file(raw)
    ref_env, ref_decoded = validate_file(reference)
    if ref_decoded["main"]["g"]["a"] != "none" or "profiles" not in ref_env["f"]:
        raise ValueError("Reference does not demonstrate the open/profiles layout")
    ref_key, ref_aad = codec.derive(ref_env, None, None)
    for section in hc._sec_list(ref_env["j"]):
        _, wrapped, sidecar = unpack_profile(section, ref_key, ref_aad)
        if wrapped or sidecar is not None:
            raise ValueError("Reference is not direct HPC1 without sidecars")
    if original["main"]["g"]["a"] != "lock_all":
        raise ValueError("This migration is limited to the observed lock_all source")
    key, aad = codec.derive(env, None, None)
    new_env = copy.deepcopy(env)
    features = copy.deepcopy(env["f"])
    if add_profiles and "profiles" not in features:
        features.append("profiles")
    new_env["f"] = features
    new_key, new_aad = codec.derive(new_env, None, None)
    main_clear = hc._dec_section(env["i"], key, aad)
    edits = {("g", "a"): "none"}
    if add_profiles:
        edits[("c",)] = features
    if combined:
        edits[("g", "v")], edits[("u",)] = NOTE, URL
    new_main = replace_values(main_clear, edits)
    new_env["i"]["b"], new_env["i"]["c"] = seal(
        new_key, new_aad + b"\0" + env["i"]["a"].encode(), new_main
    )
    migration = []
    before_sections = hc._sec_list(env["j"])
    after_sections = hc._sec_list(new_env["j"])
    for before, after in zip(before_sections, after_sections):
        profile, wrapped, sidecar = unpack_profile(before, key, aad)
        changed = False
        if relocate:
            if sidecar is not None and set(before["d"]) != {"a", "b"}:
                raise ValueError("Unknown sidecar metadata would be lost")
            profile, changed = migrate_payload(profile, sidecar)
            after.pop("d", None)
        elif sidecar is not None:
            nonce, cipher = seal(
                new_key, new_aad + b"\0" + before["a"].encode() + b":x", sidecar
            )
            after["d"]["a"], after["d"]["b"] = nonce, cipher
        after["b"], after["c"] = seal(
            new_key, new_aad + b"\0" + before["a"].encode(), profile
        )
        migration.append(
            dict(
                label=before["a"],
                hpr1_removed=wrapped,
                sidecar_relocated_to_existing_customPayload=changed,
            )
        )
    depth, outer = open_original(raw)
    edits_outer = {
        ("f",): features,
        ("i", "b"): new_env["i"]["b"],
        ("i", "c"): new_env["i"]["c"],
        ("j",): new_env["j"],
    }
    new_outer = replace_values(outer, edits_outer)
    nonce, cipher = seal(codec.OUTER_KEY, codec.OUTER_AAD, new_outer)
    output = bytes.fromhex(nonce + cipher)
    for _ in range(depth):
        output = output.decode("latin-1").encode("utf-8")
    final = codec.decrypt(output)
    if not equal(connection_view(original), connection_view(final)):
        raise AssertionError("Effective connection parameters changed")
    checked, checked_main, tags = authenticate_pure(output)
    if checked_main != new_main or not equal(checked, new_env):
        raise AssertionError("Independent AEAD verification differs")
    for name in env.keys() - {"i", "j", "f"}:
        if not equal(env[name], checked[name]):
            raise AssertionError("Unedited envelope metadata changed")
    for name in env["i"].keys() - {"b", "c"}:
        if not equal(env["i"][name], checked["i"][name]):
            raise AssertionError("Unknown main section metadata changed")
    paths = differences(original["main"], final["main"])
    return output, dict(
        access_mode="none",
        features_before=env["f"],
        features_after=features,
        changed_main_paths=["main." + ".".join(p) for p in paths],
        profiles=migration,
        profile_grammar="HPC1",
        effective_connection_parameters_preserved=True,
        unedited_hpc1_binary_fields_preserved=True,
        unknown_envelope_values_preserved=True,
        pure_python_aead_tags_verified=tags,
        import_result="PENDING_MANUAL_TEST",
        editability_result="PENDING_MANUAL_TEST",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--reference", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    source, reference = args.source.read_bytes(), args.reference.read_bytes()
    reference_env, reference_decoded = validate_file(reference)
    control = rewrap(reference, reference_decoded)
    cases = [
        (
            "A_owned_open_rewrap",
            control,
            dict(import_result="PENDING_MANUAL_TEST", changes="none"),
        )
    ]
    for case, settings in [
        ("D_open_layout", {}),
        ("E_open_layout_combined", {"combined": True}),
        ("diagnostics/B_hpc1_only", {"add_profiles": False, "relocate": False}),
        ("diagnostics/C_hpc1_profiles", {"relocate": False}),
    ]:
        data, record = convert(source, reference, **settings)
        cases.append((case, data, record))
    args.output_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    records = []
    for case, data, record in cases:
        private_write(args.output_dir / (case + ".hc"), data)
        records.append(
            dict(
                case=case,
                sha256=hashlib.sha256(data).hexdigest(),
                bytes=len(data),
                **record,
            )
        )
    report = dict(
        source_sha256=hashlib.sha256(source).hexdigest(),
        owned_reference_sha256=hashlib.sha256(reference).hexdigest(),
        cases=records,
        main_l_and_note_style_not_copied_from_reference=True,
        root_cause_status="Structural incompatibility observed; exact vendor failure pending controlled import",
    )
    private_write(
        args.output_dir / "open_layout_matrix.json",
        (json.dumps(report, indent=2) + "\n").encode(),
    )
    print(
        "Generated owned baseline, two full-layout candidates and two isolated diagnostics. Local AEAD/data invariants pass; Android pending."
    )


if __name__ == "__main__":
    main()
