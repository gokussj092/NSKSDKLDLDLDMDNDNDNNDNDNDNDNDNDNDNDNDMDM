#!/usr/bin/env python3
"""Generate the public, data-only file-format catalogue for the existing C8 API.

Canonical sources: C0_FORMAT_MATRIX.csv + active C8 worker route overrides.
The Android asset is used only to identify already bundled native routes.
No script path, runtime implementation, keys or developer inventory are emitted.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
OUTPUT = ROOT / "cloud/web/content/file-formats.json"
ANDROID = ROOT / "android/app/src/main/assets/decoder_catalog.json"

# User-input fields already accepted by the C3/C8 worker; never infer credentials.
CREDENTIAL_FIELDS = {
    "hc": ["password", "hwid"],
    "npvs": ["password", "publicKey", "recipientKey"],
    "tut": ["password"],
    "ua": ["password"],
    "1ftnl": ["password"],
    "v2box": ["password"],
}


def existing_unlocked() -> tuple[int | None, dict[str, dict]]:
    """Preserve vetted Unlocked capabilities in this SAME generated catalog.

    The source of truth is file-formats.json itself; no second manifest or
    implicit eligibility based on decryption support is permitted.
    """
    if not OUTPUT.is_file():
        return None, {}
    previous = json.loads(OUTPUT.read_text(encoding="utf-8"))
    revision = previous.get("unlockedRevision")
    markers = {}
    target_ids = set()
    for item in previous.get("formats", []):
        if "unlockedExport" not in item:
            continue
        suffix = item.get("suffix")
        value = item["unlockedExport"]
        if (not isinstance(suffix, str) or suffix in markers or
                not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,15}", suffix) or
                not isinstance(value, dict) or set(value) != {"targetAppId", "name", "banner"}):
            raise ValueError("INVALID_UNLOCKED_MARKER")
        target, name, banner = value["targetAppId"], value["name"], value["banner"]
        if (not isinstance(target, str) or
                not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,47}", target) or
                target in target_ids or not isinstance(name, str) or
                not name or name != name.strip() or len(name) > 80 or
                any(ord(c) < 32 or 127 <= ord(c) <= 159 or
                    0x202A <= ord(c) <= 0x202E or
                    0x2066 <= ord(c) <= 0x2069 for c in name) or
                banner not in ("none", "spdecode-html")):
            raise ValueError("INVALID_UNLOCKED_MARKER")
        target_ids.add(target)
        markers[suffix] = value
    if revision is not None:
        if type(revision) is not int or not (1 <= revision <= 100000):
            raise ValueError("INVALID_UNLOCKED_REVISION")
    elif markers:
        raise ValueError("UNLOCKED_REVISION_REQUIRED")
    return revision, markers


def generate() -> dict:
    from cloud.workers.python.engine import load_runtime_file_engines

    mobile = json.loads(ANDROID.read_text(encoding="utf-8"))
    if mobile.get("schemaVersion") != 4:
        raise ValueError("Unsupported current Android inventory version")
    native = {entry["suffix"] for entry in mobile["entries"]}
    if len(native) != len(mobile["entries"]):
        raise ValueError("Duplicate native suffix")
    # The NUR .solid route is bundled independently of the pinned 239 entries.
    native.add("solid")
    worker = load_runtime_file_engines()
    if not native.issubset(worker):
        raise ValueError("A bundled native route is absent from the C8 inventory")
    if not worker:
        raise ValueError("No server formats")

    unlocked_revision, unlocked = existing_unlocked()
    unknown = set(unlocked) - set(worker)
    if unknown:
        raise ValueError("UNLOCKED_FORMAT_NO_LONGER_SUPPORTED: " + ",".join(sorted(unknown)))

    formats = []
    for suffix, details in sorted(worker.items(), key=lambda pair: (-len(pair[0]), pair[0])):
        if (len(suffix) > 64 or not re.fullmatch(r"[\w.-]+", suffix, re.UNICODE) or
                suffix != suffix.lower()):
            raise ValueError("Unusable filename suffix in engine inventory")
        name = details["name"]
        if not isinstance(name, str) or not name.strip() or len(name) > 120:
            raise ValueError("Invalid public format name")
        entry = {
            "suffix": suffix,
            "name": name,
            "kind": "file",
            "offlineSupported": suffix in native,
            "cloudSupported": True,
            "credentialFields": CREDENTIAL_FIELDS.get(suffix, []),
        }
        if suffix in unlocked:
            entry["unlockedExport"] = unlocked[suffix]
        formats.append(entry)
    generated = {
        "schemaVersion": 1,
        "detection": {
            "rule": "longest-filename-suffix",
            "caseInsensitive": True,
            "separator": ".",
        },
        "formats": formats,
    }
    if unlocked_revision is not None:
        generated["unlockedRevision"] = unlocked_revision
    return generated


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Regenerate the committed public data file")
    options = parser.parse_args()
    expected = json.dumps(generate(), ensure_ascii=False, indent=2) + "\n"
    if options.write:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(expected, encoding="utf-8")
    elif not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != expected:
        raise SystemExit("Public formats are stale: python scripts/cloud_formats_catalog.py --write")
    print("Public Cloud format catalogue matches all currently registered file engines.")


if __name__ == "__main__":
    main()
