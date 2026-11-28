#!/usr/bin/env python3
"""Engine entry point for V2Ray Injector 1.4.2 .v2k files and Xray JSON.

Thin adapter over v2ray_injector.py (no new crypto, no network: the
``catalog`` fetch is never used here). The engine runs
``[python, file_decoder.py, input.v2k]``; no credentials exist for
this format, so stdin is never read. Content dispatch, same functions
the CLI uses: text starting with ``V2K1|`` opens with parse_v2k()
(plain or envelope-encrypted); anything else must be an Xray-core
JSON config and opens with import_xray_json(). Anything else is
exit 1 (the engine reports DECODE_FAILED).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

if __package__:
    from .v2ray_injector import import_xray_json, parse_v2k
else:
    from v2ray_injector import import_xray_json, parse_v2k


def decode_bytes(data: bytes) -> dict:
    """One .v2k file (or Xray JSON saved as .v2k) -> result dict."""
    text = data.decode("utf-8-sig").strip()
    if text.startswith("V2K1|"):
        return parse_v2k(text)
    return import_xray_json(text)


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    try:
        data = Path(sys.argv[1]).read_bytes()
    except OSError:
        return 2
    try:
        result = decode_bytes(data)
    except (ValueError, UnicodeError, TypeError):
        return 1
    sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
