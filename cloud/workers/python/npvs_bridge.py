#!/usr/bin/env python3
"""NPVS credentials on stdin. Choose signed or historical NPV reader by header.

This is NOT a second attempt after wrong password, signature, recipient or tag.
Historical NPVT1/NPVTSUB1 belongs to a different plaintext/comma envelope.
"""
from __future__ import annotations
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))


def legacy_json(raw: bytes) -> str:
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError("Input too large")
    if raw.startswith(b"NPVTSUB1"):
        remainder = raw[len(b"NPVTSUB1"):]
    elif raw.startswith(b"NPVT1"):
        remainder = raw[len(b"NPVT1"):]
    else:
        raise ValueError("Unknown legacy header")
    segments = remainder.decode("utf-8").strip().split(",")
    if len(segments) < 2 or not segments[1]:
        raise ValueError("Invalid legacy container")
    from decoders.Python import NPVTUNNEL as legacy
    tables = legacy.load_whitebox_state()
    clear = legacy.decrypt_logic(segments[1], *tables)
    if not clear:
        raise ValueError("Legacy decoder rejected input")
    result = json.loads(clear)
    if not isinstance(result, (dict, list)):
        raise ValueError("Legacy decoder returned no JSON document")
    # The old run() returns Telegram-decorated text and drops list entries.
    # Reuse its actual cipher but preserve the entire JSON document.
    return json.dumps(result, ensure_ascii=False, indent=2)


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    try:
        raw = Path(sys.argv[1]).read_bytes()
        if raw.startswith(b"NPVS"):
            # Explicit version selection BEFORE authentication. Do not retry
            # a failed v1 tag with the v5 codec or vice versa.
            if len(raw) < 5 or raw[4] not in (1, 5, 6):
                sys.stdout.write(json.dumps({"workerError": "NPVS_PROTECTION_UNSUPPORTED"}))
                return 3
            if raw[4] == 1:
                from decoders.Python.npvs_v1 import main as legacy_v1_main
                sys.argv.append("--credentials-stdin")
                return legacy_v1_main()
            from decoders.Python.npvs import main as signed_main
            sys.argv.append("--credentials-stdin")
            return signed_main()
        if not raw.startswith((b"NPVT1", b"NPVTSUB1")):
            return 1
        payload = sys.stdin.buffer.read(8193)
        if len(payload) > 8192:
            return 2
        credentials = json.loads(payload) if payload else {}
        if not isinstance(credentials, dict) or credentials:
            sys.stdout.write(json.dumps({"workerError": "INVALID_CREDENTIALS"}))
            return 3
        sys.stdout.write(legacy_json(raw))
        return 0
    except (OSError, UnicodeError, ValueError, TypeError):
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
