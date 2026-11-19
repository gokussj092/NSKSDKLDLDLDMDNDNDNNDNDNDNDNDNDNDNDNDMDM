"""Host-harness tests for the offline C++ n15 decoder.

Drives the built host harness (default /tmp/hc-n15-harness-build/hc_harness,
override with HC_HARNESS) against the sanitized synthetic fixtures in
tests/fixtures/ and the owner-supplied real samples in
/home/hatch/workspace/http-custom-update/drive/ (skipped when absent).

No real credential is used anywhere in this file: the only password passed
is the synthetic fixture password ("synthetic-n15-test-password") and the
fixed wrong-password probe ("wrong-password-for-test"). The 3 real
password-protected samples are covered only for their negative behaviour
here; their positive open needs the owner's test password supplied at
runtime (see REPRODUCE.md).

Run: <venv python> -m pytest tests/test_hc_n15.py -v
"""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOSSIER = HERE.parent
FIXTURES = HERE / "fixtures"
DRIVE = Path("/home/hatch/workspace/http-custom-update/drive")
VENV_PY = "/home/hatch/workspace/http-custom-update/venv/bin/python"
REF = DOSSIER / "tools" / "ref_decrypt.py"
HARNESS = os.environ.get("HC_HARNESS", "/tmp/hc-n15-harness-build/hc_harness")
SYNTHETIC_PASSWORD = "synthetic-n15-test-password"
WRONG_PASSWORD = "wrong-password-for-test"

NO_PASSWORD = [
    "Test Oppen.hc",
    "Test bloquear usuário y contraseña.hc",
    "Test bloqueo de root2.hc",
    "Test bloqueo inicio de sesión con hwid.hc",
    "Test desbloqueo payload.hc",
]
PROTECTED = [
    "Test bloqueo de operador.hc",
    "Test bloqueo de root.hc",
    "Test password2.hc",
]
UNSUPPORTED = [
    "Test bloqueo password y hwid.hc",
    "Test password.hc",
    "Test hwid.hc",
    "Test bloqueo ID de acceso.hc",
]
PROFILE_FIELDS = ["label", "name", "protocol", "host", "port", "username",
                  "password", "payload", "mode", "flags", "updated_at_ms"]


def run_harness(path, password=None):
    cmd = [HARNESS, str(path)]
    if password is not None:
        cmd.append(password)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return proc.returncode, proc.stdout, proc.stderr.strip()


def run_reference(path, password=None):
    cmd = [VENV_PY, str(REF), str(path)]
    if password is not None:
        cmd.append(password)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return proc.returncode, proc.stdout, proc.stderr.strip()


def norm_profiles(result):
    out = []
    for p in result.get("config", []):
        entry = {k: p.get(k) for k in PROFILE_FIELDS}
        entry["options"] = p.get("options", {})
        if "custom_payload_sidecar" in p:
            entry["custom_payload_sidecar"] = p["custom_payload_sidecar"]
        out.append(entry)
    return out


@unittest.skipUnless(Path(HARNESS).exists(), f"harness not built: {HARNESS}")
class HcN15HarnessTests(unittest.TestCase):
    def test_synthetic_open(self):
        rc, out, _err = run_harness(FIXTURES / "synthetic_n15_open.hc")
        self.assertEqual(rc, 0, _err)
        result = json.loads(out)
        self.assertEqual(result["app_version"], "8.0.22 Patch 2 (934)")
        self.assertEqual(len(result["config"]), 1)
        profile = result["config"][0]
        self.assertEqual(profile["name"], "synthetic-slowdns")
        self.assertEqual(profile["host"], "203.0.113.10")
        self.assertEqual(profile["port"], 53)
        self.assertEqual(profile["custom_payload_sidecar"],
                         "synthetic-custom-payload")

    def test_synthetic_protected_opens_with_synthetic_password(self):
        rc, out, _err = run_harness(FIXTURES / "synthetic_n15_protected.hc",
                                    SYNTHETIC_PASSWORD)
        self.assertEqual(rc, 0, _err)
        result = json.loads(out)
        self.assertEqual([p["label"] for p in result["config"]], ["s1", "s0"])
        # s1 is the HPR1-wrapped profile: the :r section key must have worked.
        self.assertEqual(result["config"][0]["name"], "synthetic-slowdns")

    def test_synthetic_protected_requires_password(self):
        rc, _out, err = run_harness(FIXTURES / "synthetic_n15_protected.hc")
        self.assertNotEqual(rc, 0)
        self.assertEqual(err, "ERROR PASSWORD_REQUIRED")

    def test_synthetic_protected_rejects_wrong_password(self):
        rc, _out, err = run_harness(FIXTURES / "synthetic_n15_protected.hc",
                                    WRONG_PASSWORD)
        self.assertNotEqual(rc, 0)
        self.assertEqual(err, "ERROR AUTH_FAILED")

    def test_synthetic_tampered_and_truncated_rejected(self):
        rc, _out, err = run_harness(FIXTURES / "synthetic_n15_tampered.hc")
        self.assertNotEqual(rc, 0)
        self.assertIn(err, ("ERROR AUTH_FAILED", "ERROR HC_UNRECOGNIZED_FORMAT"))
        rc, _out, err = run_harness(FIXTURES / "synthetic_n15_truncated.hc")
        self.assertNotEqual(rc, 0)
        self.assertEqual(err, "ERROR HC_UNRECOGNIZED_FORMAT")

    @unittest.skipUnless(DRIVE.exists(), "real samples not present")
    def test_real_no_password_match_reference(self):
        for name in NO_PASSWORD:
            with self.subTest(name=name):
                rc, out, err = run_harness(DRIVE / name)
                self.assertEqual(rc, 0, err)
                cpp = json.loads(out)
                self.assertEqual(len(cpp["config"]), 2, name)
                rrc, rout, rerr = run_reference(DRIVE / name)
                self.assertEqual(rrc, 0, rerr)
                ref = json.loads(rout)
                self.assertEqual(norm_profiles(cpp), norm_profiles(ref), name)
                self.assertEqual(cpp["app_version"], ref["app_version"], name)

    @unittest.skipUnless(DRIVE.exists(), "real samples not present")
    def test_real_protected_negative_behaviour(self):
        for name in PROTECTED:
            with self.subTest(name=name):
                rc, _out, err = run_harness(DRIVE / name)
                self.assertNotEqual(rc, 0)
                self.assertEqual(err, "ERROR PASSWORD_REQUIRED")
                rc, _out, err = run_harness(DRIVE / name, WRONG_PASSWORD)
                self.assertNotEqual(rc, 0)
                self.assertEqual(err, "ERROR AUTH_FAILED")

    @unittest.skipUnless(DRIVE.exists(), "real samples not present")
    def test_real_unsupported_fail_cleanly(self):
        for name in UNSUPPORTED:
            with self.subTest(name=name):
                rc, _out, err = run_harness(DRIVE / name)
                self.assertNotEqual(rc, 0)
                self.assertEqual(err, "ERROR HC_UNSUPPORTED_SCHEMA", name)


if __name__ == "__main__":
    unittest.main()
