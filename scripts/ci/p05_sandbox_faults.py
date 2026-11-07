#!/usr/bin/env python3
"""P05 CI-only Docker fault injection using first-party Python code, never APKs.

Requires a prebuilt spdecode-apk-tools image and a preloaded, verified JADX
volume. All runs are network-isolated, unprivileged, read-only and ephemeral.
This is a lab check, NOT a production admission or user workload runner.
"""
from __future__ import annotations

import argparse
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import uuid


CACHE = "spdecode-apk-tools-cache"
CACHE_TARGET = "/opt/spdecode/scripts/apk_analysis/cache"

POLICY_CODE = r"""
import errno, os, pathlib, subprocess, sys
assert os.geteuid() == 65532
status = pathlib.Path("/proc/self/status").read_text()
caps = next(line.split()[1] for line in status.splitlines() if line.startswith("CapEff:"))
assert int(caps, 16) == 0
assert set(os.listdir("/sys/class/net")) == {"lo"}
try:
    pathlib.Path("/opt/spdecode/p05-denied").write_bytes(b"deny")
except OSError as exc:
    assert exc.errno in (errno.EROFS, errno.EACCES)
else:
    raise AssertionError("Root filesystem writable")
script = pathlib.Path("/tmp/probe.sh")
script.write_text("#!/bin/sh\nexit 0\n")
script.chmod(0o700)
try:
    subprocess.run([str(script)], check=False)
except OSError as exc:
    assert exc.errno in (errno.EACCES, errno.EPERM)
else:
    raise AssertionError("tmpfs allows execution")
cg = pathlib.Path("/sys/fs/cgroup")
cpu = cg / "cpu.max"
if cpu.exists():
    quota, period = cpu.read_text().split()
    assert quota != "max" and int(quota) / int(period) <= 0.51
pids = cg / "pids.max"
if pids.exists():
    assert pids.read_text().strip() != "max"
print("POLICY_ENFORCED")
"""

DISK_CODE = r"""
import errno, pathlib, sys
try:
    with pathlib.Path("/tmp/pressure").open("wb") as out:
        for i in range(20):
            out.write(b"x" * 1024 * 1024)
            out.flush()
except OSError as exc:
    if exc.errno == errno.ENOSPC:
        print("TMPFS_ENOSPC")
        sys.exit(0)
    raise
sys.exit("tmpfs quota was not enforced")
"""

MEMORY_CODE = r"""
# Touch actual pages to enforce a cgroup OOM, not just virtual reservation.
buffer = bytearray(512 * 1024 * 1024)
for index in range(0, len(buffer), 4096):
    buffer[index] = 1
raise SystemExit("memory limit was not enforced")
"""


def safe_name() -> str:
    return "p05-fault-" + uuid.uuid4().hex[:16]


def command(image: str, name: str, *, memory: str = "128m",
            tmpfs: str = "8m", cache: bool = False) -> list[str]:
    parts = [
        "docker", "run", "--rm", "--name", name, "--network", "none",
        "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--user", "65532:65532",
        "--memory", memory, "--pids-limit", "64", "--cpus", "0.5",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=" + tmpfs,
    ]
    if cache:
        parts.extend(["--mount",
                      "type=volume,source=" + CACHE + ",target=" + CACHE_TARGET + ",readonly"])
    return parts + [image]


def checked_run(image: str, code: str, case: str, *, expected: int = 0,
                memory: str = "128m", tmpfs: str = "8m",
                marker: str | None = None) -> None:
    name = safe_name()
    cmd = command(image, name, memory=memory, tmpfs=tmpfs) + [
        "python", "-B", "-c", code,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=50)
    except subprocess.TimeoutExpired as exc:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=20)
        raise AssertionError(case + ": unexpected runner timeout") from exc
    if result.returncode != expected or (marker and marker not in result.stdout):
        # No raw stdout/stderr: production APKs must never be included in logs.
        raise AssertionError(case + ": unexpected exit/status " + str(result.returncode))


def interrupted_run(image: str) -> None:
    name = safe_name()
    cmd = command(image, name) + [
        "python", "-B", "-c", "import time; time.sleep(120)",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, start_new_session=True)
    started = False
    try:
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise AssertionError("timeout: container exited before fault")
            probe = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", name],
                                   capture_output=True, text=True, timeout=10)
            if probe.returncode == 0 and probe.stdout.strip() == "true":
                started = True
                break
            time.sleep(0.25)
        if not started:
            raise AssertionError("timeout: container never entered running state")
        try:
            proc.communicate(timeout=2)
            raise AssertionError("timeout: long-running container finished unexpectedly")
        except subprocess.TimeoutExpired:
            pass
    finally:
        # Kill the *known fresh CI-only* container even if assertions fail.
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=20)
        try:
            proc.communicate(timeout=8)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate(timeout=8)
    for _ in range(20):
        probe = subprocess.run(["docker", "inspect", name],
                               capture_output=True, timeout=10)
        if probe.returncode != 0:
            return
        time.sleep(0.25)
    raise AssertionError("timeout: orphaned analysis container")


def verify_cached_resource(image: str) -> None:
    name = safe_name()
    cmd = command(image, name, memory="512m", tmpfs="64m", cache=True) + [
        "python", "-B", "cloud/apk_analysis/runtime_preflight.py", "--check",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=80)
    if result.returncode:
        raise AssertionError("recovery: offline preflight failed")
    try:
        summary = json.loads(result.stdout)
    except ValueError as exc:
        raise AssertionError("recovery: preflight did not return JSON") from exc
    if summary.get("jadx_cache") != "HASH_VERIFIED" or summary.get("network_required_for_analysis") is not False:
        raise AssertionError("recovery: verified offline resource was not retained")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="spdecode-apk-tools:p05")
    parser.add_argument("--output", type=Path, required=True)
    opts = parser.parse_args()
    results = {}
    try:
        checked_run(opts.image, POLICY_CODE, "security", marker="POLICY_ENFORCED")
        results["sandbox_security_and_cpu_pid_policy"] = "PASS"
        checked_run(opts.image, DISK_CODE, "disk", marker="TMPFS_ENOSPC")
        results["tmpfs_disk_quota_enforced"] = "PASS"
        checked_run(opts.image, MEMORY_CODE, "memory", expected=137, memory="96m")
        results["cgroup_memory_oom_enforced"] = "PASS"
        interrupted_run(opts.image)
        results["interruption_container_removed"] = "PASS"
        verify_cached_resource(opts.image)
        results["verified_jadx_cache_survives_faults_offline"] = "PASS"
        summary = {"schema_version": 1, "scope": "FIRST_PARTY_CI_FAULTS_ONLY",
                   "production_enabled": False, "third_party_apks_tested": False,
                   "results": results}
    except (OSError, ValueError, subprocess.SubprocessError, AssertionError) as exc:
        summary = {"schema_version": 1, "scope": "FIRST_PARTY_CI_FAULTS_ONLY",
                   "production_enabled": False, "results": results,
                   "status": "FAIL", "failed_case": str(exc)[:160]}
        opts.output.write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n")
        print("P05 Docker fault tests FAILED: " + str(exc)[:160])
        return 1
    opts.output.write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n")
    print("P05 Docker fault tests PASS: " + ", ".join(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
