"""C2 deterministic validation: no runtime names, shell paths, or secrets from callers."""
from __future__ import annotations

import os
import json
import tempfile
import unittest
from pathlib import Path

from engine import (
    DecodeFailure, MAX_INPUT_BYTES, ROOT, _child_env,
    decode_file, load_file_engines,
)

class FileEngineTests(unittest.TestCase):
    def test_catalog_contains_240_source_exact_paths(self):
        engines = load_file_engines()
        self.assertEqual(len(engines), 240)
        self.assertEqual(engines["solid"]["runtime"], "python")
        self.assertEqual(engines["hat"]["runtime"], "node")
        self.assertIn("php", {row["runtime"] for row in engines.values()})
        self.assertTrue(all(Path(entry["source"]).is_file() for entry in engines.values()))

    def test_invalid_format_never_falls_back_to_other_key(self):
        for ext in ("../tls", "tls;cat", ".tls", "", "unlisted", "/tmp/input.tls"):
            with self.subTest(ext=ext), self.assertRaises(DecodeFailure) as caught:
                decode_file(ext, b"arbitrary")
            self.assertEqual(caught.exception.code, "UNSUPPORTED_FORMAT")

    def test_input_size_and_empty_bytes(self):
        for payload, code in [(b"", "INVALID_INPUT"), (b"x" * (MAX_INPUT_BYTES + 1), "INPUT_TOO_LARGE")]:
            with self.subTest(code=code), self.assertRaises(DecodeFailure) as caught:
                decode_file("tls", payload)
            self.assertEqual(caught.exception.code, code)

    def test_signed_npvs_worker_matches_source_decoder(self):
        """Actual signed v5 bytes, through the Cloud child-process adapter."""
        from scripts.android_npvs_fixture_export import export

        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)
            export(output)
            contents=(output/"npvs-v5-appkey.npvs").read_bytes()
            expected=json.loads((output/"npvs-v5-appkey.json").read_text("utf-8"))
            received=decode_file("npvs", contents)
            self.assertEqual(received["status"], "success")
            self.assertFalse(received["isPartial"])
            self.assertEqual(json.loads(received["rawText"]), expected)
            self.assertEqual(received["structuredJson"], expected)

    def test_subprocess_environment_removes_secrets(self):
        os.environ["CLOUD_WORKER_TOKEN"] = "private-test-only-do-not-ship"
        try:
            env = _child_env("/tmp/private")
            self.assertNotIn("CLOUD_WORKER_TOKEN", env)
            self.assertNotIn("DATABASE_URL", env)
            self.assertEqual(env["PYTHONPATH"], str(ROOT))
            self.assertEqual(env["HOME"], "/tmp/private")
        finally:
            os.environ.pop("CLOUD_WORKER_TOKEN", None)

if __name__ == "__main__":
    unittest.main()
