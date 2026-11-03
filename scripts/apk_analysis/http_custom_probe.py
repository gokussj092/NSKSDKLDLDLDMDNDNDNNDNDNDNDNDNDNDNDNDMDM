#!/usr/bin/env python3
"""Inspect authenticated HCX4 metadata without emitting configuration material.

This is a diagnostic, not a decoder or a substitute for full JSON validation.
Exit 3 means the envelope authenticated but the reader is not verified for it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from decoders.Python.apps.HTTP_Custom import codec


def inspect(data: bytes) -> dict:
    envelope = codec.open_envelope(data)
    schema, schedule = envelope.get("b"), envelope.get("e")
    extra = envelope.get("p")
    pending = schema == 11 and schedule in ("n13", "n14")
    return {
        "kind": "http-custom-envelope-diagnostic",
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "outer": "HCX4",
        "outerAuthenticated": True,
        "schema": schema if type(schema) is int else None,
        "schedule": schedule if schedule in ("n11", "n12", "n13", "n14") else None,
        "buildMetadata": envelope.get("n") if type(envelope.get("n")) is int else None,
        "passwordFlag": envelope.get("h") if type(envelope.get("h")) is int else None,
        "extraProtectionPresent": isinstance(extra, dict),
        "extraProtectionShape": sorted(set(extra) & {"a", "b", "c", "d", "e"}) if isinstance(extra, dict) else [],
        "encryptedSectionCount": len(envelope["j"]) if isinstance(envelope.get("j"), list) else None,
        "decryptionVerified": False,
        "status": "PENDING_EXTRA_PROTECTION" if pending and isinstance(extra, dict) else "INSPECTION_ONLY",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    args = parser.parse_args()
    try:
        with args.file.open("rb") as stream:
            report = inspect(stream.read(codec.MAX_FILE_BYTES + 1))
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 3 if report["status"] == "PENDING_EXTRA_PROTECTION" else 0
    except (OSError, codec.HCError, ValueError, TypeError):
        print("HCX4 inspection failed; no configuration emitted.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
