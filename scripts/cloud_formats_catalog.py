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
    "npvs": ["password", "publicKey"],
    "tut": ["password"],
    "ua": ["password"],
    "1ftnl": ["password"],
    "v2box": ["password"],
}


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

    formats = []
    for suffix, details in sorted(worker.items(), key=lambda pair: (-len(pair[0]), pair[0])):
        if (len(suffix) > 64 or not re.fullmatch(r"[\w.-]+", suffix, re.UNICODE) or
                suffix != suffix.lower()):
            raise ValueError("Unusable filename suffix in engine inventory")
        name = details["name"]
        if not isinstance(name, str) or not name.strip() or len(name) > 120:
            raise ValueError("Invalid public format name")
        formats.append({
            "suffix": suffix,
            "name": name,
            "kind": "file",
            "offlineSupported": suffix in native,
            "cloudSupported": True,
            "credentialFields": CREDENTIAL_FIELDS.get(suffix, []),
        })
    return {
        "schemaVersion": 1,
        "detection": {
            "rule": "longest-filename-suffix",
            "caseInsensitive": True,
            "separator": ".",
        },
        "formats": formats,
    }


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
