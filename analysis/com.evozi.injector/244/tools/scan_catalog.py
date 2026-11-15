#!/usr/bin/env python3
"""Reproduce the pending, static catalog-source investigation for build244."""
import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

UPLOAD_SHA256 = "2eeab20e7a2193d63730fbae3dcee8ac439b4f644e45465640ed80c68a92e6e4"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("private", type=Path)
    parser.add_argument("--upload", type=Path, required=True)
    args = parser.parse_args()
    if hashlib.sha256(args.upload.read_bytes()).hexdigest() != UPLOAD_SHA256:
        raise ValueError("UPLOAD_HASH_MISMATCH")
    root = Path(__file__).resolve().parents[4]
    tools = root / "analysis/_intake/http-injector-catalog-2026-11-09/tools"
    for script in ("inventory.py", "frame_inventory.py", "metadata_inventory.py"):
        subprocess.run([sys.executable, str(tools / script), str(args.private)],
                       check=True, timeout=60)
    output = args.private / "unpacked"
    output.mkdir(exist_ok=True, mode=0o700)
    subprocess.run([
        sys.executable, str(tools / "historical/httpinjector_650_unpack_native.py"),
        str(args.upload), "--output-dir", str(output),
    ], check=True, timeout=60)
    for path in output.glob("*.unpacked"):
        path.chmod(0o600)
    subprocess.run([sys.executable, str(tools / "recovered_inventory.py"),
                    str(args.private)], check=True, timeout=60)


if __name__ == "__main__":
    main()
