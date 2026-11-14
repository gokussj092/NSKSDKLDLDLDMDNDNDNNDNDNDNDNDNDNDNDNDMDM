#!/usr/bin/env python3
"""Install an operator-supplied DTunnel updater ID without printing its value."""
import argparse
import json
import os
import re
import tempfile
from pathlib import Path


def configure(source, environment):
    if source.stat().st_size > 16384:
        raise ValueError("credential file too large")
    value = json.loads(source.read_text(encoding="utf-8"))
    request_id = value.get("user_id") if isinstance(value, dict) else None
    if not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:@+/-]{1,512}", request_id):
        raise ValueError("credential file must contain a valid authorized user_id")
    text = environment.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if not line.startswith("SPDECODE_DTUNNEL_REQUEST_ID=")]
    lines.append("SPDECODE_DTUNNEL_REQUEST_ID=" + request_id)
    descriptor, temporary = tempfile.mkstemp(prefix=".catalog-auth-", dir=environment.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write("\n".join(lines) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, environment)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("environment", type=Path)
    args = parser.parse_args()
    try:
        configure(args.source, args.environment)
    except (OSError, ValueError):
        parser.exit(1, "DTunnel configuration failed: check the private credentials JSON and cloud.env permissions.\n")
    print("Authorized DTunnel updater ID configured; value not displayed.")


if __name__ == "__main__":
    main()
