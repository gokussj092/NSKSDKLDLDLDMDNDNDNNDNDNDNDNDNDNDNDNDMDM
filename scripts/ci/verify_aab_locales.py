#!/usr/bin/env python3
"""Verify Play AAB installs all SP-DECODE locales, without language splits.

Run from repository root:
  python scripts/ci/verify_aab_locales.py --source-only
  python scripts/ci/verify_aab_locales.py android/app/build/outputs/bundle/release/app-release.aab

Reads official BundleConfig.pb wire fields (BundleConfig.optimizations = 2,
Optimizations.splits_config = 1, SplitsConfig.split_dimension = 1;
SplitDimension.value = 1, LANGUAGE = 3, negate = 2).
No bundletool, Android SDK, external Python packages, or signing keys needed.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[2]
GRADLE = ROOT / "android/app/build.gradle.kts"
REGISTRY = ROOT / "android/app/src/main/java/com/ghostdeveloper/spdecode/SupportedLanguages.kt"
RES = ROOT / "android/app/src/main/res"
# Android resource qualifier uses 'in' for the registered 'id' locale.
QUALIFIERS = {"pt-BR": "pt-rBR", "id": "in"}


def _varint(data: bytes, index: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 70, 7):
        if index >= len(data):
            raise ValueError("Truncated protobuf varint")
        byte = data[index]
        index += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, index
    raise ValueError("Oversized protobuf varint")


def _fields(data: bytes) -> list[tuple[int, int, int | bytes]]:
    fields = []
    index = 0
    while index < len(data):
        key, index = _varint(data, index)
        number, wire = key >> 3, key & 7
        if number == 0:
            raise ValueError("Invalid protobuf field 0")
        if wire == 0:
            value, index = _varint(data, index)
        elif wire == 2:
            length, index = _varint(data, index)
            if length > len(data) - index:
                raise ValueError("Truncated protobuf field")
            value = data[index:index + length]
            index += length
        elif wire == 1:
            if index + 8 > len(data):
                raise ValueError("Truncated protobuf fixed64")
            value = data[index:index + 8]
            index += 8
        elif wire == 5:
            if index + 4 > len(data):
                raise ValueError("Truncated protobuf fixed32")
            value = data[index:index + 4]
            index += 4
        else:
            raise ValueError("Unsupported protobuf wire type")
        fields.append((number, wire, value))
    return fields


def _messages(data: bytes, number: int) -> list[bytes]:
    return [value for field, wire, value in _fields(data)
            if field == number and wire == 2 and isinstance(value, bytes)]


def _values(data: bytes, number: int) -> list[int]:
    return [value for field, wire, value in _fields(data)
            if field == number and wire == 0 and isinstance(value, int)]


def check_bundle_config(data: bytes) -> None:
    """Fail unless the actual AAB explicitly disables LANGUAGE splits."""
    if not data or len(data) > 1024 * 1024:
        raise ValueError("Missing or oversized BundleConfig.pb")
    optimizations = _messages(data, 2)
    if len(optimizations) != 1:
        raise ValueError("BundleConfig missing unique optimizations")
    splits = _messages(optimizations[0], 1)
    if len(splits) != 1:
        raise ValueError("BundleConfig missing unique splits_config")
    dimensions = _messages(splits[0], 1)
    language = [d for d in dimensions if 3 in _values(d, 1)]
    if len(language) != 1 or _values(language[0], 2) != [1]:
        raise ValueError("AAB LANGUAGE splits enabled or not explicitly disabled")


def check_sources(root: Path = ROOT) -> list[str]:
    gradle = (root / "android/app/build.gradle.kts").read_text(encoding="utf-8")
    # Enforce the exact Play bundle DSL, not android.splits (ignored for AAB).
    if not re.search(r"bundle\s*\{\s*language\s*\{\s*enableSplit\s*=\s*false\s*\}", gradle):
        raise ValueError("Gradle must set android.bundle.language.enableSplit = false")
    text = (root / "android/app/src/main/java/com/ghostdeveloper/spdecode/SupportedLanguages.kt").read_text(encoding="utf-8")
    tags = re.findall(r'SupportedLanguage\("([^"]+)"', text)
    if not tags or tags.count("system") != 1 or len(tags) != len(set(tags)):
        raise ValueError("Invalid or duplicate language registry entries")
    supported = [tag for tag in tags if tag != "system"]
    if len(supported) < 14:
        raise ValueError("Unexpectedly reduced supported locale inventory")
    block = re.search(r"resourceConfigurations\s*\+=\s*listOf\(([^)]*)\)", gradle)
    if not block:
        raise ValueError("Missing Android resourceConfigurations list")
    included = re.findall(r'"([^"]+)"', block.group(1))
    required = [QUALIFIERS.get(tag, tag) for tag in supported]
    if set(included) != set(required) or len(included) != len(required):
        raise ValueError(f"Bundled resource locales disagree with picker: {included!r} != {required!r}")
    for tag, qualifier in zip(supported, required):
        folder = "values" if tag == "en" else "values-" + qualifier
        path = root / "android/app/src/main/res" / folder / "strings.xml"
        if not path.is_file() or "<string " not in path.read_text(encoding="utf-8"):
            raise ValueError(f"Missing strings.xml for {tag}: {path}")
    return supported


def check_aab(path: Path) -> None:
    with ZipFile(path) as archive:
        names = set(archive.namelist())
        if "BundleConfig.pb" not in names or "base/resources.pb" not in names:
            raise ValueError("AAB is missing BundleConfig.pb or base/resources.pb")
        check_bundle_config(archive.read("BundleConfig.pb"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("aab", nargs="?", type=Path)
    parser.add_argument("--source-only", action="store_true")
    args = parser.parse_args()
    if not args.source_only and args.aab is None:
        parser.error("Pass AAB file or --source-only")
    try:
        locales = check_sources()
        if args.aab is not None:
            check_aab(args.aab)
        print("PASS: all %d locales configured; Play LANGUAGE splits disabled%s" %
              (len(locales), " in built AAB" if args.aab is not None else " in Gradle"))
        return 0
    except (OSError, ValueError, KeyError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
