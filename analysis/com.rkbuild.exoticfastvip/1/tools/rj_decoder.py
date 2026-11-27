#!/usr/bin/env python3
"""Decoder for ExoticFast VIP offline-update files (.rj / .js).

The app's Update dialog (OpenVPNClient.L0) offers "Offline Update - Needs to
import .rj or .js file". Such a file is the catalog blob itself: the same
encrypted payload the server returns (block-char layer + AES-256-CBC, see
exoticfastvip.py). The APK also ships a bundled default of the same format
in res/0k.js (Version 1.0).

Usage:
    python3 rj_decoder.py update.rj [--json out.json]
    python3 rj_decoder.py update.js [--json out.json]

The decrypted catalog (all j0 fields decrypted) is printed as a summary
and, with --json, written as JSON.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from exoticfastvip import decrypt_catalog, outer_decrypt_any, summarize  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Decode an ExoticFast VIP .rj/.js update file")
    ap.add_argument("file", help=".rj or .js offline-update file")
    ap.add_argument("--json", help="write decrypted catalog JSON here")
    args = ap.parse_args()
    with open(args.file, encoding="utf-8", errors="replace") as fh:
        raw_text = fh.read()
    cat = decrypt_catalog(json.loads(outer_decrypt_any(raw_text)))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(cat, fh, ensure_ascii=False, indent=2)
        print(f"wrote {args.json}")
    print(json.dumps(summarize(cat), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
