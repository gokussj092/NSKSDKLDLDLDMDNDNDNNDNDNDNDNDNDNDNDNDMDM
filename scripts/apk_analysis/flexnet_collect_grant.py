#!/usr/bin/env python3
"""Select and verify a local Frida capture for one encrypted FlexNet file."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from decoders.Python import flexnet_b42 as codec

PREFIX = "FLEXNET_GRANT_CAPTURE "
OFFLINE_PREFIX = "FLEXNET_OFFLINE_CAPTURE "
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


def collect_offline_inner(profile: bytes, log: bytes) -> bytes:
    """Validate the v5 inner container observed after the app opens v6.

    The host cannot independently authenticate the outer v6 tag without its
    Keystore key. It validates both inner GCM tags and the entire document.
    The hash mapping relies on the local observer's trusted original call.
    """
    info = codec.inspect_profile(profile)
    if info["format"] != "FLXCFG-v6" or info["mode"] != "device-offline":
        raise codec.DecodeError("CAPTURE_FORMAT", "An offline inner capture requires a v6 profile.")
    if len(log) > MAX_LOG:
        raise codec.DecodeError("SIZE_LIMIT", "Capture log exceeds 8 MiB.")
    wanted = hashlib.sha256(profile).hexdigest()
    expected_length = len(profile) - 61
    encoded_length = ((expected_length + 2) // 3) * 4
    for line in log.decode("utf-8", errors="replace").splitlines():
        if OFFLINE_PREFIX not in line:
            continue
        capture = line.split(OFFLINE_PREFIX, 1)[1].strip().encode("utf-8")
        try:
            if len(capture) > encoded_length + 512:
                continue
            obj = codec._json(capture)
            if (not isinstance(obj, dict) or set(obj) != {"schema", "fileSha256", "innerBase64"}
                    or obj["schema"] != "flexnet-v6-opened-inner/1" or obj["fileSha256"] != wanted
                    or not isinstance(obj["innerBase64"], str) or len(obj["innerBase64"]) != encoded_length):
                continue
            inner = base64.b64decode(obj["innerBase64"], validate=True)
            if (len(inner) != expected_length or base64.b64encode(inner).decode("ascii") != obj["innerBase64"]
                    or not inner.startswith(codec.MAGIC + b"\x05\x01")):
                continue
            codec.decode(inner)  # Inner wrapping/content tags, gzip, XML and FLXFLD.
            return inner
        except (ValueError, RecursionError):
            continue
    raise codec.DecodeError("CAPTURE_NOT_FOUND", "No valid opened v5 inner container matches this v6 import.")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path)
    parser.add_argument("log", type=Path)
    parser.add_argument("output", type=Path, help="New capture JSON, or inner .flex with --offline-inner; never overwrites")
    parser.add_argument("--offline-inner", action="store_true", help="Save the v5 inner container observed during a v6 import")
    args = parser.parse_args(argv)
    try:
        with args.profile.open("rb") as handle:
            profile = handle.read(codec.MAX_INPUT + 1)
        with args.log.open("rb") as handle:
            log = handle.read(MAX_LOG + 1)
        capture = collect_offline_inner(profile, log) if args.offline_inner else collect(profile, log)
        with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
            handle.write(capture)
        if args.offline_inner:
            print("Verified v5 inner container saved; the observed app opened the v6 outer layer.")
        else:
            print("Verified capture saved for this exact file; no key or profile values printed.")
        return 0
    except codec.DecodeError as error:
        print(error.code + ": " + str(error), file=sys.stderr)
    except OSError:
        print("IO_ERROR: Cannot read inputs or create the new private capture file.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
