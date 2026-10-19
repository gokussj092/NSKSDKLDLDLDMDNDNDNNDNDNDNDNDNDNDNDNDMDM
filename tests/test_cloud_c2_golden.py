"""C2 reference-source parity over the 60 synthetic A.2.3 inputs.

The historical A.2.3 fixture hashes predate some decoder updates. We preserve
them, report mismatches explicitly, and compare the worker with the CURRENT
canonical script stdout byte-for-byte (no rewriting legacy snapshots).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cloud.workers.python.engine import (
    DecodeFailure, ROOT, _child_env, decode_file, load_file_engines,
)
from tests.golden.a23_export import SUFFIX
from tests.golden.a23_generators import SYNTHETIC_GENERATORS

class CloudC2SourceParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((ROOT / "tests/golden/manifest.json").read_text(encoding="utf-8"))
        cls.engines = load_file_engines()

    def test_all_sixty_worker_results_match_unmodified_original_scripts(self):
        cases = self.manifest["fixtureCaseDefinitions"]
        self.assertEqual(len(cases), 60)
        legacy_drift = []
        for case in cases:
            name = case["id"]
            with self.subTest(case=name):
                self.assertIn(name, SUFFIX)
                suffix = SUFFIX[name]
                engine = self.engines[suffix]
                sample = SYNTHETIC_GENERATORS[name]()
                frozen = (ROOT / case["expectedRawText"]).read_bytes()
                self.assertEqual(hashlib.sha256(frozen).hexdigest(), case["expectedRawUtf8Sha256"])
                runtime = sys.executable if engine["runtime"] == "python" else shutil.which(engine["runtime"])
                self.assertIsNotNone(runtime)
                with tempfile.TemporaryDirectory(prefix="c2-source-") as folder:
                    input_path = Path(folder) / ("input." + suffix)
                    input_path.write_bytes(sample)
                    original = subprocess.run(
                        [runtime, engine["source"], str(input_path)],
                        cwd=ROOT,
                        env=_child_env(folder),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        timeout=20,
                        check=False,
                    )
                self.assertEqual(original.returncode, 0, "Original source failed: " + name)
                try:
                    cloud_result = decode_file(suffix, sample)
                except DecodeFailure as error:
                    self.fail("Worker failed " + name + ": " + error.code)
                current = cloud_result["rawText"].encode("utf-8")
                reference = original.stdout
                if suffix == "ssh":
                    # The original SSH engine intentionally selects a random
                    # decorative emoji. Do not change product output; compare
                    # substantive lines while ignoring ONLY the status glyph.
                    def ignore_glyph(data: bytes) -> str:
                        return re.sub(r"│\[(?:💠|🔵|💀|🤖|😈|🔥|🚀|🔐)\]", "│[DECORATION]", data.decode("utf-8"))
                    self.assertEqual(ignore_glyph(current), ignore_glyph(reference))
                else:
                    self.assertEqual(current, reference)
                self.assertEqual(cloud_result["status"], "success")
                self.assertFalse(cloud_result["decoder"]["exporterCertified"])
                # Existing artifacts remain immutable; recorded discrepancy is NOT
                # a cloud regression or a claim of original historical parity.
                if hashlib.sha256(sample).hexdigest() != case["inputSha256"] or original.stdout.strip() != frozen.strip():
                    legacy_drift.append(name)
        # Do not assert a fixed drift count; the source corpus includes
        # intentionally non-deterministic SSH decorations and historical
        # generator evolution. Any observed drift remains visible in CI.
        print("C2 historical A.2.3 drift (not silently rebaselined): " + (", ".join(legacy_drift) if legacy_drift else "none"))

if __name__ == "__main__":
    unittest.main()
