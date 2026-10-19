#!/usr/bin/env python3
"""SP-DECODE Cloud C0: reproducible Android migration inventory (metadata only).

No decoder execution, file contents, ciphertext, keys or user credentials are
exported. The bot and Android code remain read-only and unaffected.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "android/app/src/main/assets/decoder_catalog.json"
MATRIX = ROOT / "docs/cloud/C0_FORMAT_MATRIX.csv"
UI_BASELINE = ROOT / "docs/cloud/C0_UI_BASELINE.json"

FIELDS = (
    "suffix", "app_name", "source_script", "source_runtime", "android_phase",
    "android_port_status", "linux_synthetic", "android_verified",
    "exporter_versions", "source_catalog",
)
PHASE_COUNTS = {"legacy": 61, "B": 81, "C": 41, "D": 16, "E": 27, "F": 13}
RUNTIME_COUNTS = {"python": 228, "node": 8, "php": 3}

# Extra Android entrypoints are outside the 239-entry file catalog.
EXTRA_SURFACES = {
    "text_protocols": "android/app/src/main/java/com/ghostdeveloper/spdecode/TextProtocolDecoder.kt",
    "text_phase_g": "android/app/src/main/java/com/ghostdeveloper/spdecode/TextPhaseGPort.kt",
    "http_injector_cloud": "android/app/src/main/java/com/ghostdeveloper/spdecode/HttpInjectorCloudPort.kt",
    "nur_server_catalog": "android/app/src/main/java/com/ghostdeveloper/spdecode/NurTunnelServerCatalog.kt",
    "hc_protected_import": "android/app/src/main/java/com/ghostdeveloper/spdecode/parity/HcHccfgPort.kt",
    "file_dispatcher": "android/app/src/main/java/com/ghostdeveloper/spdecode/parity/AndroidOfflineDecoderRouter.kt",
    "app_dispatcher": "android/app/src/main/java/com/ghostdeveloper/spdecode/MainActivity.kt",
}

# Names, not values. No content or credentials are included in reports.
PACKAGED_MATERIAL = (
    "embedded_kotlin_profiles.json", "flex_f_profiles.json",
    "generic_b_profiles.json", "hc_source_keys.json",
    "http_tweak_source_tables.json", "legacy_epro_npv2_keys.json",
    "npvs_v5_tables.b85", "nur_tunnel_server_endpoint.json",
    "renz_d_profiles.json", "ultra_c_profiles.json",
)


def fail(message: str) -> None:
    raise ValueError("C0 baseline: " + message)


def load_android_catalog() -> dict:
    doc = json.loads(CATALOG.read_text(encoding="utf-8"))
    if doc.get("schemaVersion") != 3 or doc.get("botRegisteredSuffixes") != 239:
        fail("unexpected Android catalog schema or registered count")
    if doc.get("androidNativePortSuffixes") != 239 or doc.get("androidPendingNativeSuffixes") != 0:
        fail("native Android route inventory changed")
    if doc.get("androidCertifiedSuffixes") != 0:
        fail("certification count changed; review evidence before rebaselining")
    rows = doc.get("entries")
    if not isinstance(rows, list) or len(rows) != 239:
        fail("expected exactly 239 Android catalog entries")
    if Counter(row["migrationPhase"] for row in rows) != PHASE_COUNTS:
        fail("Android phase allocation changed")
    if Counter(row["originalRuntime"] for row in rows) != RUNTIME_COUNTS:
        fail("reference runtime inventory changed")
    if doc.get("syntheticLinuxCoveredSuffixes") != 238:
        fail("synthetic Linux coverage count changed")
    suffixes = [row["suffix"] for row in rows]
    if len(set(suffixes)) != len(suffixes) or "solid" in suffixes:
        fail("duplicate suffix or NUR .solid accidentally merged into 239 catalog")
    if any(row["androidVerified"] for row in rows):
        fail("verified Android exporter coverage changed; review fixtures")
    return doc


def validate_reference_mapping(doc: dict) -> None:
    # Registry is imported only for metadata; never run decoders or the bot.
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from spdecode.registry import DECODER_REGISTRY

    expected = {row["suffix"] for row in doc["entries"]} | {"solid"}
    if set(DECODER_REGISTRY) != expected:
        fail("Android and bot registry suffix sets differ")
    for row in doc["entries"]:
        suffix = row["suffix"]
        spec = DECODER_REGISTRY[suffix]
        if (row["name"], row["script"], row["originalRuntime"]) != (
            spec.name, spec.script, spec.runtime
        ):
            fail("canonical source mapping drift for ." + suffix)
        source = ROOT / spec.script
        if not source.resolve().is_relative_to((ROOT / "decoders").resolve()):
            fail("decoder source escapes the expected directory")
        if not source.is_file():
            fail("missing source decoder for ." + suffix)
    solid = DECODER_REGISTRY["solid"]
    if (solid.script, solid.runtime) != (
        "decoders/Python/nur_tunnel_solid.py", "python"
    ):
        fail("NUR .solid mapping drift")
    if not (ROOT / solid.script).is_file():
        fail("missing NUR .solid source")


def build_rows(doc: dict) -> list[tuple[str, ...]]:
    rows = [
        (
            r["suffix"], r["name"], r["script"], r["originalRuntime"],
            r["migrationPhase"], r["androidPortStatus"],
            str(r["linuxGoldenSynthetic"]).lower(),
            str(r["androidVerified"]).lower(),
            "|".join(r["exporterVersionsVerified"]), r["sourceCatalog"],
        )
        for r in doc["entries"]
    ]
    rows.append((
        "solid", "NUR TUNNEL VPN (.solid)", "decoders/Python/nur_tunnel_solid.py",
        "python", "NUR", "experimental_nur_solid_native",
        "false", "false", "", "nur-tunnel-v1.0.8.8",
    ))
    rows.sort(key=lambda row: (-len(row[0]), row[0]))
    return rows


def render_matrix(rows: list[tuple[str, ...]]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(FIELDS)
    writer.writerows(rows)
    return stream.getvalue()


def git_blob_sha1(data: bytes) -> str:
    # Git object identity, not a cryptographic trust or secret-storage scheme.
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def verify_ui_baseline() -> None:
    doc = json.loads(UI_BASELINE.read_text(encoding="utf-8"))
    if doc.get("schemaVersion") != 1:
        fail("unexpected UI baseline version")
    checks = doc.get("uiGitBlobSha1")
    if not isinstance(checks, dict) or len(checks) != 9:
        fail("expected nine pinned UI/UX files")
    for name, sha in checks.items():
        path = ROOT / name
        if not name.startswith("android/app/src/main/java/com/ghostdeveloper/spdecode/"):
            fail("invalid UI source path")
        if not path.is_file() or git_blob_sha1(path.read_bytes()) != sha:
            fail("UI/UX source modified without explicit rebaseline: " + name)


def validate_extra_surfaces() -> None:
    for surface, name in EXTRA_SURFACES.items():
        if not (ROOT / name).is_file():
            fail("missing Android integration surface: " + surface)
    activity = (ROOT / EXTRA_SURFACES["app_dispatcher"]).read_text("utf-8")
    for marker in (
        "AndroidOfflineDecoderRouter", "TextProtocolDecoder",
        "HttpInjectorCloudPort", "NurTunnelServerCatalog",
        "decodeWithCredentials",
    ):
        if marker not in activity:
            fail("Android dispatcher entrypoint disappeared: " + marker)
    catalog_source = (ROOT / "android/app/src/main/java/com/ghostdeveloper/spdecode/parity/AndroidDecoderCatalog.kt").read_text("utf-8")
    if 'candidate.endsWith(".solid")' not in catalog_source:
        fail("special .solid Android route disappeared")


def validate_packaged_material_inventory() -> None:
    assets = ROOT / "android/app/src/main/assets"
    missing = [name for name in PACKAGED_MATERIAL if not (assets / name).is_file()]
    if missing:
        fail("packaged decoder-material filenames changed: " + ", ".join(missing))


def audit(*, write: bool = False) -> dict[str, int]:
    doc = load_android_catalog()
    validate_reference_mapping(doc)
    validate_extra_surfaces()
    validate_packaged_material_inventory()
    verify_ui_baseline()
    rows = build_rows(doc)
    if len(rows) != 240 or len({row[0] for row in rows}) != 240:
        fail("expected 240 uniquely named file routes including .solid")
    actual = render_matrix(rows)
    if write:
        MATRIX.parent.mkdir(parents=True, exist_ok=True)
        MATRIX.write_text(actual, encoding="utf-8", newline="")
    elif MATRIX.read_text(encoding="utf-8") != actual:
        fail("format matrix drift; run python scripts/cloud_c0_inventory.py --write only after reviewing mapping")
    return {
        "catalog_routes": 239,
        "special_routes": 1,
        "source_scripts": len({row[2] for row in rows}),
        "experimental_or_prototype": 240,
        "android_certified": 0,
        "ui_files_locked": 9,
        "extra_android_surfaces": len(EXTRA_SURFACES),
        "packaged_material_names": len(PACKAGED_MATERIAL),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="Verify committed C0 matrix (default)")
    group.add_argument("--write", action="store_true", help="Regenerate C0 matrix (never changes UI lock)")
    args = parser.parse_args()
    try:
        report = audit(write=args.write)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        parser.exit(1, str(exc) + "\n")
    print("[C0] Android migration inventory checked (metadata only): " + json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
