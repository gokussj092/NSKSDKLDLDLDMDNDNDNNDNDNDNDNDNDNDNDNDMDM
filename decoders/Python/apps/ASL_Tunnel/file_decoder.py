#!/usr/bin/env python3
"""CLI adapter: decode an ASL TUNNEL .asl file (or pasted CONFIG KEY).

The engine runs ``python file_decoder.py <file>``; the adapter wraps
asltunnel.decode_asl_file and prints exactly one JSON document on
stdout: the imported server config as the app reads it. Any failure
exits 1 with the reason on stderr and nothing on stdout, so the
engine never parses a partial line.

Two shapes exist and are told apart by keys (see asltunnel.py):
the Q() import config (plaintext fields) and the LCl.b custom-server
object (AES/CFB-encrypted string fields, decrypted here).

Password reporting, not enforcement: when the config has
isPassON=true, the app prompts the user for the password in field
MyPass. This decoder reports the config verbatim (isPassON and MyPass
are part of the file's own JSON) and notes the requirement on stderr;
it does not enforce device, root, expiry or installer checks.
"""
from __future__ import annotations

import json
import sys

if __package__:
    from .asltunnel import decode_asl_file
else:
    from asltunnel import decode_asl_file


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: file_decoder.py <file.asl>", file=sys.stderr)
        return 2
    try:
        result, notes = decode_asl_file(sys.argv[1])
    except (ValueError, OSError) as exc:
        print("Unable to decode .asl file: %s" % exc, file=sys.stderr)
        return 1
    for note in notes:
        print("# " + note, file=sys.stderr)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
