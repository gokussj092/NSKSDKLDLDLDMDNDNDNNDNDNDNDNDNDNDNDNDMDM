"""Dossier tests for SSC Custom (dev.epro.ssc, 96).

Runs the Python oracle cross-check (verify.py: oracle vs the real
server decoder on every fixture) and the native host harness
(build_host_harness.sh: production C++ vs the same expected JSON).
Both must pass. No real sample exists yet, so all positives are
synthetic round-trips; see RESULTS.md for the honest status.

Usage (from the repo root), stdlib unittest (also pytest-compatible):
    python3 analysis/dev.epro.ssc/96/tests/test_method.py -v
Requires a python with PyCryptodome for verify.py.
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

DOSSIER = Path(__file__).resolve().parent.parent
TOOLS = DOSSIER / "tools"
ROOT = DOSSIER.parents[2]


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))


class SscDossierTests(unittest.TestCase):
    def test_python_oracle_matches_server_decoder(self):
        proc = _run([sys.executable, str(TOOLS / "verify.py")])
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("24 passed, 0 failed", proc.stdout)

    def test_native_harness_matches_oracle(self):
        proc = _run(["bash", str(TOOLS / "build_host_harness.sh")])
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("12 passed, 0 failed", proc.stdout)

    def test_expected_json_is_valid_and_sanitized(self):
        for name in ("single_layer", "two_layer", "inner_encrypted",
                     "ssc_link"):
            data = json.loads(
                (DOSSIER / "tests" / "expected" / f"{name}.json").read_text())
            text = json.dumps(data)
            self.assertIn("example.org", text)
            self.assertTrue("dummy-not-a-real-secret" in text or
                            "dummy-user" in text)
            # No real credential material in fixtures: only dummy values.
            self.assertNotIn("ghp_", text)
            self.assertNotIn("sk_live", text)


if __name__ == "__main__":
    unittest.main()
