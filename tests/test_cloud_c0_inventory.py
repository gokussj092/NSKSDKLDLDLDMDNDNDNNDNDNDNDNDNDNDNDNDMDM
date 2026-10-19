"""C0 regression tests: Android scope, source provenance and UI freeze only.

These tests NEVER decrypt user data or load cryptographic material.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

from scripts.cloud_c0_inventory import (
    CATALOG, EXTRA_SURFACES, FIELDS, MATRIX, PACKAGED_MATERIAL,
    ROOT, UI_BASELINE, audit, build_rows, git_blob_sha1,
    load_android_catalog, render_matrix, validate_extra_surfaces,
    validate_packaged_material_inventory, validate_reference_mapping,
    verify_ui_baseline,
)


class CloudC0BaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = load_android_catalog()
        cls.rows = build_rows(cls.document)

    def test_all_239_android_routes_and_one_solid_are_frozen(self):
        self.assertEqual(len(self.rows), 240)
        self.assertEqual(len({r[0] for r in self.rows}), 240)
        self.assertEqual(sum(r[0] == "solid" for r in self.rows), 1)
        self.assertEqual(sum(r[4] == "legacy" for r in self.rows), 61)
        self.assertEqual(sum(r[4] == "B" for r in self.rows), 81)
        self.assertEqual(sum(r[4] == "C" for r in self.rows), 41)
        self.assertEqual(sum(r[4] == "D" for r in self.rows), 16)
        self.assertEqual(sum(r[4] == "E" for r in self.rows), 27)
        self.assertEqual(sum(r[4] == "F" for r in self.rows), 13)
        self.assertEqual(sum(r[4] == "NUR" for r in self.rows), 1)
        self.assertEqual([r[0] for r in self.rows],
                         sorted((r[0] for r in self.rows), key=lambda s: (-len(s), s)))
        self.assertEqual(self.document["syntheticLinuxCoveredSuffixes"], 238)
        self.assertEqual(self.document["androidCertifiedSuffixes"], 0)

    def test_canonical_python_node_php_mappings_and_source_files(self):
        validate_reference_mapping(self.document)
        self.assertEqual(len({row[2] for row in self.rows}), 77)
        self.assertEqual({r[3] for r in self.rows}, {"python", "node", "php"})
        self.assertTrue(all(r[7] == "false" for r in self.rows))

    def test_matrix_is_deterministic_and_contains_metadata_only(self):
        self.assertEqual(MATRIX.read_text(encoding="utf-8"), render_matrix(self.rows))
        self.assertEqual(len(FIELDS), 10)
        self.assertEqual(FIELDS[0], "suffix")
        self.assertEqual(FIELDS[-1], "source_catalog")
        self.assertNotIn("private_key", FIELDS)
        self.assertNotIn("password", FIELDS)

    def test_special_android_entrypoints_remain_audited(self):
        validate_extra_surfaces()
        self.assertEqual(len(EXTRA_SURFACES), 7)
        self.assertTrue((ROOT / EXTRA_SURFACES["text_phase_g"]).exists())
        self.assertTrue((ROOT / EXTRA_SURFACES["nur_server_catalog"]).exists())

    def test_ui_ux_source_files_have_exact_original_git_blob_ids(self):
        verify_ui_baseline()
        manifest = json.loads(UI_BASELINE.read_text(encoding="utf-8"))
        self.assertEqual(len(manifest["uiGitBlobSha1"]), 9)
        self.assertNotIn(
            "android/app/src/main/java/com/ghostdeveloper/spdecode/MainActivity.kt",
            manifest["uiGitBlobSha1"],
        )
        for name, sha in manifest["uiGitBlobSha1"].items():
            self.assertEqual(git_blob_sha1((ROOT / name).read_bytes()), sha)

    def test_packaged_source_material_is_classified_by_filename_only(self):
        validate_packaged_material_inventory()
        self.assertEqual(len(PACKAGED_MATERIAL), 10)
        # No secret material should appear in the committed inventory.
        inventory = MATRIX.read_text(encoding="utf-8")
        self.assertNotIn("BEGIN PRIVATE KEY", inventory)

    def test_existing_golden_corpus_is_available_as_a_reference(self):
        manifest = json.loads((ROOT / "tests/golden/manifest.json").read_text("utf-8"))
        self.assertEqual(manifest["schemaVersion"], 1)
        self.assertEqual(len(manifest["fixtureCaseDefinitions"]), 60)
        for fixture in manifest["fixtureCaseDefinitions"]:
            with self.subTest(fixture=fixture["id"]):
                expected = ROOT / fixture["expectedRawText"]
                self.assertTrue(expected.is_file())
                self.assertEqual(
                    hashlib.sha256(expected.read_bytes()).hexdigest(),
                    fixture["expectedRawUtf8Sha256"],
                )

    def test_cli_check_with_no_decoder_execution(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts/cloud_c0_inventory.py"), "--check"],
            cwd=ROOT, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('"catalog_routes": 239', proc.stdout)
        self.assertIn('"ui_files_locked": 9', proc.stdout)

    def test_audit_report_contains_no_secrets_or_file_payloads(self):
        report = audit()
        self.assertEqual(report["catalog_routes"], 239)
        self.assertEqual(report["special_routes"], 1)
        self.assertEqual(report["android_certified"], 0)
        self.assertEqual(report["source_scripts"], 77)
        self.assertEqual(report["extra_android_surfaces"], 7)
        self.assertEqual(report["packaged_material_names"], 10)


if __name__ == "__main__":
    unittest.main()
