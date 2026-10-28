#!/usr/bin/env python3
"""Prepare an existing root-owned env file without activating/restarting services."""
import argparse
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile

def prepare(path: Path, project: str, certificates: str, level: str) -> None:
    if not re.fullmatch(r"[1-9][0-9]{5,17}", project):
        raise ValueError("Invalid Google Cloud project number")
    digests = [x.strip().lower() for x in certificates.split(",")]
    if not 1 <= len(digests) <= 4 or any(not re.fullmatch(r"[a-f0-9]{64}", x) for x in digests):
        raise ValueError("Use Play App Signing SHA-256 fingerprints")
    if level not in ("tee", "strongbox"):
        raise ValueError("Invalid hardware policy")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise ValueError("Env file must be a regular file with owner-only permissions")
    lines = path.read_text().splitlines()
    current = dict(line.split("=", 1) for line in lines if "=" in line and not line.startswith("#"))
    updates = {
        "COMPOSE_PROFILES": ",".join(dict.fromkeys([x for x in current.get("COMPOSE_PROFILES", "").split(",") if x] + ["hardware-security"])),
        "CLOUD_KEY_ATTESTATION_TOKEN": current.get("CLOUD_KEY_ATTESTATION_TOKEN") or secrets.token_hex(32),
        "CLOUD_PLAY_CERT_SHA256": ",".join(digests),
        "CLOUD_GOOGLE_CLOUD_PROJECT_NUMBER": project,
        "CLOUD_KEY_ATTESTATION_LEVEL": level,
        "CLOUD_KEY_ATTESTATION_REQUIRED": "true",
        "CLOUD_ACTION_INTEGRITY_REQUIRED": "true",
        "CLOUD_INTEGRITY_MIN_DEVICE_SDK": "33",
        "CLOUD_INTEGRITY_MAX_RECENT_ACTIVITY": "3",
    }
    if len(updates["CLOUD_KEY_ATTESTATION_TOKEN"]) < 32:
        raise ValueError("Existing attestation credential is too short")
    result = [line for line in lines if line.split("=", 1)[0] not in updates]
    result += [key + "=" + value for key, value in updates.items()]
    fd, temporary = tempfile.mkstemp(prefix=".security-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write("\n".join(result) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, info.st_uid, info.st_gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", type=Path, default=Path("/etc/spdecode/cloud.env"))
    parser.add_argument("--project-number", required=True)
    parser.add_argument("--play-certificates", required=True)
    parser.add_argument("--level", choices=("tee", "strongbox"), default="tee")
    args = parser.parse_args()
    prepare(args.env, args.project_number, args.play_certificates, args.level)
    print("Security configuration prepared. Existing panel and V1 controls were preserved.")
