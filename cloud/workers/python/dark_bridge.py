#!/usr/bin/env python3
"""Select observed open Dark JSON before invoking the legacy protected reader."""
import json
import base64
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))


def main():
    try:
        raw = Path(sys.argv[1]).read_bytes()
        # Inspect only the plain outer JSON to select the new open route.
        # Existing encrypted/legacy inputs keep their original decoder.
        try:
            token = raw.decode('utf-8').strip().split('://', 1)[-1]
            outer = json.loads(base64.urlsafe_b64decode(token+'='*(-len(token)%4)))
        except (ValueError, UnicodeError): outer = None
        if isinstance(outer, dict) and not outer.get('encryptedLockedConfig'):
            from exports.dark import decode
            document = decode(raw)
            print(json.dumps(document.outer, ensure_ascii=False, indent=2))
            return 0
        from decoders.Python.DARKTUNNEL import run
        result = run(raw)
        if not result: return 1
        print(result)
        return 0
    except Exception:
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
