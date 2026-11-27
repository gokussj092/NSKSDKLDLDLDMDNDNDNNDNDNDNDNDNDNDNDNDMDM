"""Unit tests for the offline n19 port (synthetic fixtures only).

Run: HC_HARNESS=/path/to/hc_harness_n19 python -m unittest tests.test_hc_n19 -v
from the dossier directory (or set HC_HARNESS_ORIG for the n15 regression
comparisons). No real files, no credentials: the synthetic password is
's3cret-pw' and fixtures are generated deterministically by
tools/make_synthetic_n19.py. The Python reference oracle
(tools/ref_oracle/codec.py) must open every fixture too, so the fixtures
are independently valid n19/n15 files, not just self-consistent.
"""
import json, os, subprocess, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'tools'))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'tools', 'ref_oracle'))
import codec
import make_synthetic_n19 as synth

HARNESS = os.environ.get("HC_HARNESS", "./hc_harness_n19")
HARNESS_ORIG = os.environ.get("HC_HARNESS_ORIG", "./hc_harness_orig")
PW = "s3cret-pw"

def call(exe, data, pw="", hwid=""):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".hc") as f:
        f.write(data); path = f.name
    try:
        return subprocess.run([exe, path, pw, hwid], capture_output=True)
    finally:
        os.unlink(path)

class TestN19(unittest.TestCase):
    def test_open_matches_reference(self):
        data = synth.build("n19")
        r = call(HARNESS, data)
        self.assertEqual(r.returncode, 0, r.stderr.decode()[:200])
        self.assertEqual(json.loads(r.stdout), codec.decrypt(data))

    def test_protected_correct_password(self):
        data = synth.build("n19", protected=True, password=PW)
        r = call(HARNESS, data, PW)
        self.assertEqual(r.returncode, 0, r.stderr.decode()[:200])
        self.assertEqual(json.loads(r.stdout), codec.decrypt(data, password=PW))

    def test_protected_missing_password(self):
        data = synth.build("n19", protected=True, password=PW)
        r = call(HARNESS, data)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(b"PASSWORD_REQUIRED", r.stderr)

    def test_protected_wrong_password(self):
        data = synth.build("n19", protected=True, password=PW)
        r = call(HARNESS, data, "wrong")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(b"AUTH_FAILED", r.stderr)

    def test_hpr1_and_string_banner(self):
        data = synth.build("n19", hpr1=True, banner="str")
        r = call(HARNESS, data)
        self.assertEqual(r.returncode, 0, r.stderr.decode()[:200])
        got = json.loads(r.stdout)
        self.assertEqual(got, codec.decrypt(data))
        self.assertEqual(got["protections"]["tunnelBanner"], "plain-banner")

    def test_tampered_rejected(self):
        data = bytearray(synth.build("n19")); data[-30] ^= 0x01
        self.assertNotEqual(call(HARNESS, bytes(data)).returncode, 0)

    def test_n15_unchanged(self):
        data = synth.build("n15")
        rn = call(HARNESS, data); ro = call(HARNESS_ORIG, data)
        self.assertEqual(rn.returncode, 0, rn.stderr.decode()[:200])
        self.assertEqual(rn.stdout, ro.stdout)
        self.assertEqual(json.loads(rn.stdout), codec.decrypt(data))
        self.assertNotIn("remoteProxyUnlocked", json.loads(rn.stdout)["protections"])

    def test_n15_protected_unchanged(self):
        data = synth.build("n15", protected=True, password=PW)
        rn = call(HARNESS, data, PW); ro = call(HARNESS_ORIG, data, PW)
        self.assertEqual(rn.returncode, 0, rn.stderr.decode()[:200])
        self.assertEqual(rn.stdout, ro.stdout)

if __name__ == "__main__":
    unittest.main()
