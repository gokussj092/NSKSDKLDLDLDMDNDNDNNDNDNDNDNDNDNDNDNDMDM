"""Prevent the NPVS bridge from passing host tests but disappearing in Docker.

Checks the exact deployed worker image recipe. The executable smoke test in
cloud-c2.yml runs the genuine, unprivileged Docker image against synthetic
signed NPVS, covering password requests, failures and full JSON.
"""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]

class NpvsPackagingTests(unittest.TestCase):
    def test_engine_bridge_is_present_in_image_recipe(self):
        engine=(ROOT/"cloud/workers/python/engine.py").read_text()
        docker=(ROOT/"cloud/workers/python/Dockerfile").read_text()
        assert 'with_name("npvs_bridge.py")' in engine
        copy_lines=[row.strip() for row in docker.splitlines()
                    if row.strip().startswith("COPY cloud/workers/python/")]
        self.assertTrue(any("cloud/workers/python/npvs_bridge.py" in row
                            for row in copy_lines))
        self.assertIn("USER 65532:65532",docker)
        self.assertIn("from npvs_bridge import main as npvs_main",docker)

    def test_real_container_credential_cases_are_in_ci(self):
        ci=(ROOT/".github/workflows/cloud-c2.yml").read_text()
        for value in ("Verify packaged NPVS password and error contracts",
                      "docker cp tests/golden/npvs_protected_generate.py",
                      "decode_file(\"npvs\", raw, credentials=creds)",
                      "PASSWORD_REQUIRED", "AUTH_FAILED",
                      "output[\"structuredJson\"] == expected"):
            self.assertIn(value,ci)
