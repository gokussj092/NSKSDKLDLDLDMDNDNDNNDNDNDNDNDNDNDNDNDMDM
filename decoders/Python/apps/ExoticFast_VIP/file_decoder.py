#!/usr/bin/env python3
"""CLI adapter: decode an ExoticFast VIP offline-update file (.rj).

The engine runs ``python file_decoder.py <file>``; the adapter wraps
exoticfastvip.decrypt_catalog over the same encrypted envelope the
server returns (block-char layer + AES-256-CBC, then j0 fields) and
prints exactly one JSON document on stdout. Any failure exits 1 with
the reason on stderr and nothing on stdout, so the engine never parses
a partial line.

The app also accepts .js files with the same blob, but .js is a
GENERIC extension and is NOT registered as an app suffix: registering
it would claim every JavaScript file for this app. Only .rj is
registered. A .js update blob still decodes if passed to this script
directly.

The app also imports plain .ovpn profiles; .ovpn is a generic
OpenVPN profile format, NOT an ExoticFast suffix, and is not
registered. The ovpn_decoder.py helper in this directory parses such
profiles; it is not wired to the engine.
"""
from __future__ import annotations

import json
import sys

if __package__:
    from .exoticfastvip import decrypt_catalog, outer_decrypt_any
else:
    from exoticfastvip import decrypt_catalog, outer_decrypt_any


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: file_decoder.py <file.rj>", file=sys.stderr)
        return 2
    try:
        with open(sys.argv[1], "r", encoding="utf-8-sig") as stream:
            text = stream.read()
    except OSError as exc:
        print("Cannot read file: %s" % exc, file=sys.stderr)
        return 1
    try:
        result = decrypt_catalog(json.loads(outer_decrypt_any(text)))
    except (ValueError, TypeError) as exc:
        print("Unable to decode .rj file: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
