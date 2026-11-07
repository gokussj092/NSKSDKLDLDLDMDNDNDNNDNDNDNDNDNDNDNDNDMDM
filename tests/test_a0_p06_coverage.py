"""F7-A0-P06 static impact gate fixtures: no APK, remote network or decoder execution."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scripts.ci import check_a0_p06_coverage as p06


class P06CoverageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.method = "decoders/Python/apps/Example_VPN/codec.py"
        self.worker = "cloud/workers/python/catalog_vpn_bridge.py"
        self.protocol = "cloud/web/lib/example-protocol.mjs"
        self.source = "cloud/web/lib/example-source.mjs"
        self.dossier = "analysis/com.example.vpn/12"
        self.write(self.method, "raise RuntimeError('NEVER IMPORT THIS')\n")
        self.write(self.worker,
                   "from decoders.Python.apps.Example_VPN import codec\n"
                   "def work(): return codec\n")
        self.write(self.source, "export const harmless = true;\n")
        self.write(self.protocol, "import { harmless } from './example-source.mjs';\n"
                                  "export const test = harmless;\n")
        self.manifest = {"schema_version": 1, "package_name": "com.example.vpn",
                         "version_code": "12", "status": "PENDING",
                         "targets": [], "tooling": [], "dependencies": [],
                         "authorization_note": "first-party fixture",
                         "code_paths": {"provider": self.method, "worker": self.worker,
                                        "protocol": self.protocol}}
        self.write(self.dossier + "/MANIFEST.json", json.dumps(self.manifest))
        self.write("analysis/platform/apk-tooling/legacy_provider_baseline.v1.json",
                   json.dumps({"schema_version": 1, "source_commit": "synthetic",
                               "providers": [{"folder": "Example_VPN",
                                              "status": "LEGACY_UNREVIEWED"}],
                               "exceptions": []}))

    def write(self, rel, value):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(value, encoding="utf-8")

    def test_untouched_legacy_does_not_block(self):
        report = p06.audit(self.root, enforce=True)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["gate_status"], "PASS")
        self.assertEqual(report["legacy"]["unreviewed"], 1)

    def test_updated_provider_requires_updated_linked_dossier(self):
        report = p06.audit(self.root, [self.method], enforce=True)
        self.assertTrue(any(f["code"] == "CHANGED_METHOD_WITHOUT_UPDATED_DOSSIER"
                            for f in report["findings"]))
        self.assertEqual(report["gate_status"], "FAIL")
        fixed = p06.audit(self.root, [self.method, self.dossier + "/RESULTS.md"],
                          enforce=True)
        self.assertEqual(fixed["findings"], [])

    def test_transitive_python_consumer_is_listed_with_digest(self):
        report = p06.audit(self.root, [self.method, self.dossier + "/RESULTS.md"],
                           enforce=True)
        affected = {r["path"]: r for r in report["affected"]}
        self.assertIn(self.worker, affected)
        self.assertEqual(affected[self.worker]["via"], [self.method, self.worker])
        self.assertEqual(len(affected[self.worker]["sha256"]), 64)
        self.assertEqual(affected[self.worker]["dossiers"], [self.dossier])

    def test_new_cloud_worker_without_evidence_blocked(self):
        self.write("cloud/workers/python/exports/new_codec.py", "x = 1\n")
        report = p06.audit(self.root,
                           ["cloud/workers/python/exports/new_codec.py"], enforce=True)
        self.assertIn("CHANGED_METHOD_WITHOUT_UPDATED_DOSSIER",
                      [f["code"] for f in report["findings"]])

    def test_changed_cloud_protocol_requires_dossier(self):
        report = p06.audit(self.root, [self.protocol], enforce=True)
        self.assertEqual(report["gate_status"], "FAIL")
        ok = p06.audit(self.root, [self.protocol, self.dossier + "/REPRODUCE.md"],
                       enforce=True)
        self.assertEqual(ok["findings"], [])

    def test_static_js_dependency_reverse_impact(self):
        report = p06.audit(self.root, [self.source], enforce=True)
        affected = {f["path"]: f for f in report["affected"]}
        self.assertIn(self.protocol, affected)
        self.assertEqual(affected[self.protocol]["via"],
                         [self.source, self.protocol])
        self.assertIn("AFFECTED_DOSSIER_REVIEW_REQUIRED",
                      [f["code"] for f in report["findings"]])

    def test_dynamic_python_import_is_uncertainty_not_execution(self):
        self.write(self.worker, "import importlib\n"
                                "target = 'untrusted'\n"
                                "plugin = importlib.import_module(target)\n")
        report = p06.audit(self.root, [self.worker], enforce=True)
        item = next(x for x in report["affected"] if x["path"] == self.worker)
        self.assertIn("DYNAMIC_IMPORT_UNKNOWN_TARGET", item["uncertainty"])

    def test_future_route_changes_covered(self):
        route = "cloud/web/app/api/v1/decode/route.ts"
        self.write(route, "export const POST = () => null;\n")
        report = p06.audit(self.root, [route], enforce=True)
        self.assertIn("CHANGED_METHOD_WITHOUT_UPDATED_DOSSIER",
                      [f["code"] for f in report["findings"]])

    def test_unrelated_view_and_docs_do_not_block(self):
        self.write("cloud/web/lib/app-notifications.mjs", "export const x = 1;\n")
        report = p06.audit(self.root,
                           ["cloud/web/lib/app-notifications.mjs", "docs/change.md"],
                           enforce=True)
        self.assertEqual(report["findings"], [])

    def test_new_legacy_provider_reported_not_silently_approved(self):
        self.write("decoders/Python/apps/New_VPN/codec.py", "x=1\n")
        report = p06.audit(self.root)
        self.assertEqual(report["legacy"]["added_since_baseline"], ["New_VPN"])
        self.assertEqual(report["approval"], "NONE_GRANTED")

    def test_unmapped_legacy_consumer_is_visible(self):
        report = p06.audit(self.root, [self.source], enforce=True)
        self.assertIn(self.source, report["unresolved_consumers"])
        self.assertEqual(report["gate_status"], "FAIL")

    def test_changed_path_rejects_traversal(self):
        with self.assertRaises(p06.CoverageError):
            p06.audit(self.root, ["../secrets"], enforce=True)


if __name__ == "__main__":
    unittest.main()
