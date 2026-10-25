#!/usr/bin/env python3
"""Deterministic Android catalog: 61 legacy + 81 generic + 41 Ultra + 16 RENZ + 27 special + 13 independent native.

Phases B-F activate all 178 bot-only source-matched suffixes.
The original .ost route remains legacy; No pending file suffixes remain; exporter-version certification is separate.
The public catalog contains no crypto keys. Generation is reproducible.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

A24_BATCH10 = ("phc","mina","vpnlite","cloudy","mij","fnnetwork","uwu","sksrv","maya","xui")
A24_BATCH20 = ("at","nm","ost","sbr","pcx","nt","pb","aro","ipt","gold")
A24_BATCH15 = ("agn","cly","fɴ","jvc","jvi","v2i","sksrv.png","xscks","mrc","mtl","jez","hrt","ziv","epro","npv2")
A24_FINAL11 = ("rez","rezl","tvt","stk","xtp","roy","sksplus","sks","sut","tnl","ssh")
A24_EXTRA4 = ("ht","htb","hat","ehil")
A24_FINAL7 = ("dark","ehi","npv4","npvt","sip","ssc","hc")
A24_NPVS = ("npvs",)
PROTO = ("v2","tls") + A24_BATCH10 + A24_BATCH20 + A24_BATCH15 + A24_FINAL11 + A24_EXTRA4 + A24_FINAL7 + ("lnk",) + A24_NPVS
CATALOG = ROOT / "android/app/src/main/assets/decoder_catalog.json"

# Group only by the bot's selected script, not by extension guesses. Existing
# .ost remains the original OUSS port; its special Ultra fallback is not moved.
MIGRATION_PHASES = {
    "decoders/Python/generic_aes.py": "B",
    "decoders/Python/generic_des.py": "B",
    "decoders/Python/ultra.py": "C",
    "decoders/Python/renz.py": "D",
}
PHASE_E_SCRIPTS = frozenset({
    "sentinel.py", "itv.py", "eut.py", "v2box_export.py", "slipnet.py",
    "juanscript.py", "wyrlite.py", "wyrvpn.py", "intvpn.py", "fthp.py",
    "ar_pro.py", "ec.py", "xor_family.py",
})
PHASE_F_SCRIPTS = frozenset({
    "izph.py", "flex.py", "n4.py", "crev.py", "ktr.py", "zoba.py",
    "ltm.py", "dev.py", "vn7.py",
})
EXPECTED_NEW_BY_PHASE = {"B": 81, "C": 41, "D": 16, "E": 27, "F": 13}


def phase_for(script: str) -> str:
    if script in MIGRATION_PHASES:
        return MIGRATION_PHASES[script]
    if script.startswith("decoders/Python/"):
        name = script.removeprefix("decoders/Python/")
        if name in PHASE_E_SCRIPTS:
            return "E"
        if name in PHASE_F_SCRIPTS:
            return "F"
    raise ValueError(f"Unassigned bot-only Android migration route: {script}")


def legacy_status(suffix: str) -> str:
    if suffix == "v2":
        return "prototype_two_synthetic_cases"
    if suffix == "tls":
        return "prototype_tls_aesgcm_synthetic_case"
    for status, group in (
        ("experimental_batch10_synthetic", A24_BATCH10),
        ("experimental_batch20_synthetic", A24_BATCH20),
        ("experimental_batch15_synthetic", A24_BATCH15),
        ("experimental_final11_synthetic", A24_FINAL11),
        ("experimental_final_extra4_synthetic", A24_EXTRA4),
        ("experimental_final7_synthetic_subset", A24_FINAL7),
        ("experimental_native_npvs_v5", A24_NPVS),
    ):
        if suffix in group:
            return status
    if suffix == "lnk":
        return "experimental_linklayer_ver6_synthetic"
    raise ValueError(f"Existing Android port lost its status: {suffix}")


def generate() -> dict:
    from spdecode.registry import DECODER_REGISTRY

    # The 239-route legacy catalog is pinned. NUR .solid is independently
    # supported by Android and the bot, and must never be misclassified as a
    # migrated legacy profile or silently alter their parity hashes.
    solid = DECODER_REGISTRY.get("solid")
    if solid is not None and (
        solid.script != "decoders/Python/nur_tunnel_solid.py"
        or solid.runtime != "python"
        or solid.name != "NUR TUNNEL VPN (.solid)"
    ):
        raise ValueError("NUR .solid registry route changed unexpectedly")
    # C8 overlays must not mutate the immutable 239-route C0 Android baseline.
    # HTTP Door, AboWaged and CREEB Injector are new Cloud-only extensions; CREEB VPN
    # overrides the historical .crev route in the live bot registry.
    baseline_registry = {
        suffix: spec for suffix, spec in DECODER_REGISTRY.items()
        if suffix not in ("solid", "1ftnl", "awg", "creeb", "kyz", "stp")
    }
    from dataclasses import replace
    if "crev" in baseline_registry:
        baseline_registry["crev"] = replace(
            baseline_registry["crev"], name="CREV",
            script="decoders/Python/crev.py", runtime="python"
        )
    legacy = json.loads((ROOT / "decoders.json").read_text("utf-8"))["decoders"]
    if len(legacy) != 61 or len(baseline_registry) != 239:
        raise ValueError("Expected 61 original and 239 existing migration formats")
    if set(legacy) - set(baseline_registry):
        raise ValueError("Android original formats are missing from bot registry")
    if len(PROTO) != 61 or set(PROTO) != set(legacy):
        raise ValueError("Original 61 native Android routes changed")
    rows = []
    count_by_phase = {phase: 0 for phase in EXPECTED_NEW_BY_PHASE}
    enabled_generic = 0
    enabled_ultra = 0
    enabled_renz = 0
    enabled_special = 0
    enabled_independent = 0
    for suffix, spec in baseline_registry.items():
        old = legacy.get(suffix)
        if old is not None:
            if (spec.name, spec.script, spec.runtime) != (
                old["name"], old["script"], old["runtime"]
            ):
                raise ValueError(f"Original Android decoder was remapped: .{suffix}")
            row = {
                "suffix": suffix,
                "name": spec.name,
                "script": spec.script,
                "originalRuntime": spec.runtime,
                "linuxGoldenSynthetic": suffix != "npvs",
                "androidPortStatus": legacy_status(suffix),
                "androidVerified": False,
                "exporterVersionsVerified": ["124.0.37"] if suffix == "npvs" else [],
                "migrationPhase": "legacy",
                "sourceCatalog": "decoders.json",
            }
        else:
            phase = phase_for(spec.script)
            count_by_phase[phase] += 1
            is_generic = phase == "B"
            is_ultra = phase == "C"
            is_renz = phase == "D"
            is_special = phase == "E"
            is_independent = phase == "F"
            if is_generic:
                enabled_generic += 1
            if is_ultra:
                enabled_ultra += 1
            if is_renz:
                enabled_renz += 1
            if is_special:
                enabled_special += 1
            if is_independent:
                enabled_independent += 1
            if is_generic:
                native_status = (
                    "experimental_generic_des_ecb_synthetic"
                    if spec.script.endswith("generic_des.py")
                    else "experimental_generic_aes_gcm_synthetic"
                )
            elif is_ultra:
                native_status = "experimental_ultra_sandok_argon2id_synthetic"
            elif is_renz:
                native_status = "experimental_renz_aes_xxtea_threefish_synthetic"
            elif is_special:
                native_status = "experimental_special_13_engines_synthetic"
            elif is_independent:
                native_status = "experimental_independent_9_engines_synthetic"
            else:
                native_status = "registered_not_implemented"
            row = {
                "suffix": suffix,
                "name": spec.name,
                "script": spec.script,
                "originalRuntime": spec.runtime,
                # B has source-derived reference vectors separate from A23;
                # C-F still have no native synthetic parity baseline.
                "linuxGoldenSynthetic": is_generic or is_ultra or is_renz or is_special or is_independent,
                "androidPortStatus": native_status,
                "androidVerified": False,
                "exporterVersionsVerified": [],
                "migrationPhase": phase,
                "sourceCatalog": "spdecode.registry",
            }
        rows.append(row)
    if count_by_phase != EXPECTED_NEW_BY_PHASE or enabled_generic != 81 or enabled_ultra != 41 or enabled_renz != 16 or enabled_special != 27 or enabled_independent != 13:
        raise ValueError(
            f"Migration/native families drifted: {count_by_phase}, {enabled_generic}, {enabled_ultra}, {enabled_renz}, {enabled_special}, {enabled_independent}"
        )
    if len({row["suffix"] for row in rows}) != 239:
        raise ValueError("Duplicate suffix in generated catalog")
    rows.sort(key=lambda item: (-len(item["suffix"]), item["suffix"]))
    return {
        "schemaVersion": 3,
        "inventorySource": "spdecode.registry.DECODER_REGISTRY",
        "legacyInventorySource": "decoders.json",
        "botRegisteredSuffixes": 239,
        "androidExistingSuffixes": 61,
        "androidGenericNativeSuffixes": enabled_generic,
        "androidUltraNativeSuffixes": enabled_ultra,
        "androidRenzNativeSuffixes": enabled_renz,
        "androidSpecialNativeSuffixes": enabled_special,
        "androidIndependentNativeSuffixes": enabled_independent,
        "androidNativePortSuffixes": 61 + enabled_generic + enabled_ultra + enabled_renz + enabled_special + enabled_independent,
        "androidPendingNativeSuffixes": 178 - enabled_generic - enabled_ultra - enabled_renz - enabled_special - enabled_independent,
        "migrationCounts": count_by_phase,
        "syntheticLinuxCoveredSuffixes": sum(bool(row["linuxGoldenSynthetic"]) for row in rows),
        "androidCertifiedSuffixes": 0,
        "androidPrototypeSuffixes": list(PROTO),
        "entries": rows,
    }


def public_catalog(full: dict) -> dict:
    """APK metadata only: never embed runtime paths or Python implementation details."""
    hidden = {"inventorySource", "legacyInventorySource"}
    public = {key: value for key, value in full.items() if key not in hidden}
    public["schemaVersion"] = 4
    public["entries"] = [
        {key: row[key] for key in
            ("suffix", "name", "androidPortStatus", "androidVerified", "migrationPhase")}
        for row in full["entries"]
    ]
    return public


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    expected = json.dumps(public_catalog(generate()), ensure_ascii=False, indent=2) + "\n"
    if args.write:
        CATALOG.parent.mkdir(parents=True, exist_ok=True)
        CATALOG.write_text(expected, encoding="utf-8")
    elif not CATALOG.is_file() or CATALOG.read_text("utf-8") != expected:
        raise SystemExit("Android catalog is stale: python scripts/android_a24_catalog.py --write")
    print("[F] 239 formats: 61 legacy + 81 generic + 41 Ultra + 16 RENZ + 27 special + 13 independent native; 0 pending; 0 certified")


if __name__ == "__main__":
    main()
