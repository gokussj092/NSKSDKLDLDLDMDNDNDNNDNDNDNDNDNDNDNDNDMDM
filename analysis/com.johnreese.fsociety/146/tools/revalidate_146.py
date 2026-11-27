#!/usr/bin/env python3
"""Revalidate the REESE 3.23.28 merge: selftest, synthetic-sample open via
all three entry points, and the legacy negative paths.

No network. No real user data (the sample is synthetic TEST-NET).
"""
from __future__ import annotations
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "decoders/Python/apps/REESE_TUNNEL/reese_tunnel.py"
FIXTURE = ROOT / ("analysis/com.johnreese.fsociety/146/tests/fixtures/"
                  "sample_synthetic.rt")


def load():
    spec = importlib.util.spec_from_file_location("reese146", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    proof: dict = {"app": "REESE TUNNEL", "version_code": 146}
    mod = load()
    out = subprocess.run([sys.executable, str(SCRIPT), "selftest"],
                         capture_output=True, text=True, stdin=subprocess.DEVNULL)
    proof["selftest"] = {"ok": out.returncode == 0,
                         "output": out.stdout.strip()}
    raw = FIXTURE.read_bytes()
    doc = mod.decode(raw, hwid="ABC-123", password="test123")
    proof["decode()"] = {"meta_name": doc["meta"]["name"],
                         "ssh_host": doc["config"]["sshHost"]}
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".txt",
                                    delete=False) as handle:
        handle.write("test123")
        pw_file = handle.name
    cli = subprocess.run(
        [sys.executable, str(SCRIPT), str(FIXTURE),
         "--hwid", "ABC-123", "--password-file", pw_file],
        capture_output=True, text=True, stdin=subprocess.DEVNULL)
    Path(pw_file).unlink(missing_ok=True)
    proof["engine_cli"] = {"ok": cli.returncode == 0}
    try:
        mod.decode(raw, hwid="ABC-123", password="wrong")
        proof["wrong_password"] = {"failed_as_expected": False}
    except mod.RSE5Error as exc:
        proof["wrong_password"] = {"failed_as_expected": True,
                                   "code": exc.code}
    try:
        mod.decode(b"RSE1" + b"\x00" * 10, hwid="X", password="y")
        proof["truncated_legacy"] = {"failed_as_expected": False}
    except mod.RSE5Error as exc:
        proof["truncated_legacy"] = {"failed_as_expected": True,
                                     "code": exc.code}
    print(json.dumps(proof, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
