#!/usr/bin/env python3
"""F7-A0-P03 fail-closed policy check; does not build/run sandbox images.

Verifies the tool candidate registry against unchanged research script hashes,
and checks that the separate Compose blueprint retains core isolation. Full
container runtime / E2E tests are explicitly later approval gates.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = "analysis/platform/apk-tooling/execution_policy.v1.json"
SNAPSHOT_PATH = "analysis/platform/apk-tooling/tool_sources.v1.json"


class PolicyError(ValueError):
    pass


def check(root: Path = ROOT) -> dict:
    root = Path(root)
    policy = json.loads((root / POLICY_PATH).read_text("utf-8"))
    snapshot = json.loads((root / SNAPSHOT_PATH).read_text("utf-8"))
    if policy.get("schema_version") != 1 or policy.get("execution_defaults") != "DENY":
        raise PolicyError("Approval policy must deny by default")
    if policy.get("commercial_worker_enabled") is not False or policy.get("android_upload_enabled") is not False:
        raise PolicyError("P03 may not enable production service or APK uploads")
    config = policy.get("runtime", {})
    expected = {
        "network_mode": "none", "read_only_rootfs": True, "drop_capabilities": ["ALL"],
        "no_new_privileges": True, "run_as_uid": 65532, "run_as_gid": 65532,
        "share_docker_socket": False, "host_credential_mounts": False,
    }
    for key, value in expected.items():
        if config.get(key) != value:
            raise PolicyError("Unsafe runtime setting: " + key)
    if config.get("mem_limit_mb", 0) < 2560 or config.get("pids_limit", 0) > 128:
        raise PolicyError("Runtime resources do not match expected P03 isolation")
    storage = policy.get("storage", {})
    for key, value in {
        "runtime_cache_access": "READ_ONLY",
        "maintenance_cache_access": "READ_WRITE_WITH_CHECKSUM_CHECKS",
        "job_workspace": "PER_JOB_UUID_PRIVATE_ROOT",
        "job_lifecycle": "DELETE_ONLY_AFTER_TRUSTED_DURABLE_RESULT_RECEIPT_OR_TERMINAL_CLOSURE",
        "human_pending": "KEEP_JOB_UNTIL_REVIEW_OR_RETENTION_DECISION",
        "stale_cleanup": "ONLY_TRUSTED_TERMINAL_JOBS",
    }.items():
        if storage.get(key) != value:
            raise PolicyError("Unsafe cache/workspace policy: " + key)
    approved = 0
    registered = {t["path"]: t for t in snapshot["sources"]}
    seen = set()
    for entry in policy.get("profiles", []):
        path = entry.get("path")
        if path in seen or path not in registered:
            raise PolicyError("Unregistered/duplicated tool candidate")
        seen.add(path)
        if entry.get("auto_run") is not False or not entry.get("approval", "").startswith("PENDING_"):
            raise PolicyError("Candidate cannot be automatically executed")
        if entry.get("network") != "DENIED":
            raise PolicyError("Job tool cannot request network in offline P03")
        if not isinstance(entry.get("timeout_seconds"), int) or not 10 <= entry["timeout_seconds"] <= 1800:
            raise PolicyError("Tool timeout missing/unbounded")
        if not isinstance(entry.get("input_max_mib"), int) or not 1 <= entry["input_max_mib"] <= 512:
            raise PolicyError("Tool input size missing/unbounded")
        file = root / path
        content = file.read_bytes()
        oid = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
        if oid != entry.get("git_blob_sha1") or oid != registered[path]["git_blob_sha1"]:
            raise PolicyError("Research tool source has changed: " + path)
    if not seen:
        raise PolicyError("Missing review candidates")
    compose = (root / "cloud/apk_analysis/compose.yaml").read_text("utf-8")
    docker = (root / "cloud/apk_analysis/Dockerfile").read_text("utf-8")
    ignore = (root / "cloud/apk_analysis/Dockerfile.dockerignore").read_text("utf-8")
    blocks = compose.split("  apk-resource-preload:", 1)
    if len(blocks) != 2:
        raise PolicyError("Maintenance service must be separate")
    runtime = blocks[0].split("  apk-runtime-preflight:", 1)
    if len(runtime) != 2:
        raise PolicyError("Offline runtime preflight service missing")
    runtime = runtime[1]
    for item in ("network_mode: none", "read_only: true", "cap_drop: [\"ALL\"]",
                 "no-new-privileges:true", "user: \"65532:65532\"",
                 "apk-tool-cache:/opt/spdecode/scripts/apk_analysis/cache:ro",
                 "mem_limit: 3072m", "pids_limit: 64"):
        if item not in runtime:
            raise PolicyError("Container security control missing: " + item)
    if any(x in compose for x in ("privileged: true", "/var/run/docker.sock", "ports:")):
        raise PolicyError("Docker socket, privileged or host port prohibited")
    if "network_mode: none" in blocks[1]:
        # Maintenance intentionally has egress for pinned download. Detect
        # accidental shared offline settings without wrongly approving network.
        raise PolicyError("JADX maintenance networking must be independently reviewed")
    for required in ("pip install --no-cache-dir -r /tmp/apk-analysis-requirements.txt",
                     "COPY scripts/apk_analysis/inspect_apk.py scripts/apk_analysis/decompile.py",
                     "USER 65532:65532"):
        if required not in docker:
            raise PolicyError("Tool image contract missing: " + required)
    if any(x in runtime for x in ("pip install", "apt-get", "decompile.py\", \"--install")):
        raise PolicyError("Runtime cannot install resources per APK")
    for file in ("!scripts/apk_analysis/inspect_apk.py", "!scripts/apk_analysis/decompile.py",
                 "!scripts/apk_analysis/requirements.txt"):
        if file not in ignore:
            raise PolicyError("Image source allowlist incomplete")
    if "**/cache/**" not in ignore or "**/work/**" not in ignore:
        raise PolicyError("Image build might capture private job files")
    return {"reviewed_candidates": len(seen), "automatically_approved": approved,
            "runtime_network": "NONE", "cache":"PERSISTENT_TRUSTED_RESOURCES",
            "per_job_cleanup": "AFTER_DURABLE_RECEIPT_ONLY", "deployment": "NOT_ENABLED"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        print(json.dumps(check(args.repo_root), sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print("F7-A0-P03 FAIL: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
