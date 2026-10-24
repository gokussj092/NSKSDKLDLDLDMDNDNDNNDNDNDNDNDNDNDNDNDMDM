#!/usr/bin/env python3
"""Select and verify a local Frida capture for one encrypted FlexNet file."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from decoders.Python import flexnet_b42 as codec

PREFIX = "FLEXNET_GRANT_CAPTURE "
MAX_LOG = 8 * 1024 * 1024


def collect(profile: bytes, log: bytes) -> bytes:
    if len(log) > MAX_LOG:
        raise codec.DecodeError("SIZE_LIMIT", "Capture log exceeds 8 MiB.")
    codec.inspect_profile(profile)
    wanted = hashlib.sha256(profile).hexdigest()
    for line in log.decode("utf-8", errors="replace").splitlines():
        if PREFIX not in line:
            continue
        capture = line.split(PREFIX, 1)[1].strip().encode("utf-8")
        try:
            if len(capture) > codec.MAX_GRANT_CAPTURE:
                continue
            obj = json.loads(capture)
            if not isinstance(obj, dict) or obj.get("fileSha256") != wanted:
                continue
            # Full decode, including all GCM tags, gzip, XML and protected fields.
            # Nothing is saved if the recorded key cannot open this exact file.
            codec.decode(profile, grant_capture=capture)
            return capture + b"\n"
        except (ValueError, RecursionError):
            continue
    raise codec.DecodeError("CAPTURE_NOT_FOUND", "No valid successful import capture matches this file.")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path)
    parser.add_argument("log", type=Path)
    parser.add_argument("output", type=Path, help="New local capture JSON; never overwrites an existing file")
    args = parser.parse_args(argv)
    try:
        with args.profile.open("rb") as handle:
            profile = handle.read(codec.MAX_INPUT + 1)
        with args.log.open("rb") as handle:
            log = handle.read(MAX_LOG + 1)
        capture = collect(profile, log)
        with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
            handle.write(capture)
        print("Verified capture saved for this exact file; no key or profile values printed.")
        return 0
    except codec.DecodeError as error:
        print(error.code + ": " + str(error), file=sys.stderr)
    except OSError:
        print("IO_ERROR: Cannot read inputs or create the new private capture file.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
