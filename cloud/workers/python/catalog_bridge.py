#!/usr/bin/env python3
"""NUR encrypted server-catalog parser. Processes provided bytes only.

The future remote fetcher/SSRF policy is NOT part of this worker (C3).
Uses the exact authenticated envelope and nested-field method of .solid.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from decoders.Python.nur_tunnel_solid import _open, _text, _values, DecodeError

def decode_catalog(payload: bytes) -> dict:
    clear, _ = _open(_text(payload))
    try:
        obj = json.loads(clear)
    except (ValueError, RecursionError):
        raise DecodeError("INVALID_JSON", "Invalid authenticated catalog.") from None
    if (not isinstance(obj, dict)
        or not isinstance(obj.get("Version"), str)
        or not isinstance(obj.get("Servers"), list)
        or not isinstance(obj.get("Networks"), list)
        or not all(isinstance(entry, dict) for entry in obj["Servers"] + obj["Networks"])):
        raise DecodeError("WRONG_DOCUMENT", "Expected NUR server catalog.")
    result = _values(obj, {"decrypted_fields": 0})
    return result

def main() -> int:
    if len(sys.argv) != 2:
        return 2
    try:
        data = Path(sys.argv[1]).read_bytes()
        clear = decode_catalog(data)
    except (DecodeError, OSError):
        return 1
    sys.stdout.write(json.dumps(clear, indent=2, ensure_ascii=False) + "\n")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
