"""Offline F7-A0 metadata-gate tests; no APK, network or third-party imports."""
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "check_method_evidence", Path(__file__).resolve().parents[1] / "scripts/ci/check_method_evidence.py"
)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class MethodEvidenceGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.toolpath = "scripts/apk_analysis/inspect_apk.py"
        self.put(self.toolpath, "print('fixture')\n")
        self.put("scripts/apk_analysis/requirements.txt", "androguard==4.1.4\n")
        content = (self.root / self.toolpath).read_bytes()
        self.put("analysis/platform/apk-tooling/tool_sources.v1.json", json.dumps({
            "schema_version": 1,
            "sources": [{"path": self.toolpath, "size": len(content),
                         "git_blob_sha1": hashlib.sha1(f"blob {len(content)}\0".encode() + content).hexdigest(),
                         "approval": "UNREVIEWED"}],
        }))
        self.app_path = "analysis/com.example.vpn/12"
        dossier = {
            "schema_version": 1, "package_name": "com.example.vpn", "version_code": "12",
            "status": "PENDING", "targets": [{"kind": "catalog", "status": "PENDING"}],
            "tooling": [], "dependencies": [], "authorization_note": "fixture",
            "code_paths": {"codec": "decoders/Python/apps/Example_VPN/codec.py",
                           "broker": "cloud/web/lib/example-protocol.mjs"},
        }
        self.put(f"{self.app_path}/MANIFEST.json", json.dumps(dossier))
        for f in ("ANALYSIS.md", "REPRODUCE.md", "RESULTS.md", "DEPENDENCIES.md", "dependencies.lock.json"):
            self.put(f"{self.app_path}/{f}", "{}" if f.endswith(".json") else "fixture\n")
        self.put(f"{self.app_path}/tools/inspect.py", "print('fixture')\n")
        self.put(f"{self.app_path}/tests/test_fixture.py", "def test_fixture(): pass\n")

    def put(self, path, content):
        dest = self.root / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")

    def audit(self, *paths, enforce=True):
        return mod.audit(self.root, None, list(paths), enforce)

    def test_audit_finds_tools_and_pinned_dependencies_without_approving(self):
        report = self.audit(enforce=False)
        self.assertEqual(report["summary"]["script_count"], 1)
        self.assertEqual(report["summary"]["pinned_requirement_count"], 1)
        self.assertEqual(report["summary"]["approved_for_unattended_execution"], 0)
        self.assertEqual(report["snapshot_problems"], [])

    def test_change_method_with_dossier_is_accepted(self):
        report = self.audit("decoders/Python/apps/Example_VPN/codec.py", f"{self.app_path}/RESULTS.md")
        self.assertEqual(report["blocking_findings"], [])

    def test_change_method_without_dossier_is_rejected(self):
        report = self.audit("decoders/Python/apps/Example_VPN/codec.py")
        self.assertEqual(report["blocking_findings"][0]["code"], "MISSING_CHANGED_PROVIDER_DOSSIER")

    def test_untracked_provider_is_rejected(self):
        report = self.audit("decoders/Python/apps/New_VPN/codec.py", f"{self.app_path}/RESULTS.md")
        self.assertEqual(report["blocking_findings"][0]["code"], "MISSING_CHANGED_PROVIDER_DOSSIER")

    def test_missing_docs_and_tests_rejected(self):
        (self.root / self.app_path / "RESULTS.md").unlink()
        (self.root / self.app_path / "tests/test_fixture.py").unlink()
        report = self.audit(f"{self.app_path}/MANIFEST.json")
        self.assertEqual(report["blocking_findings"][0]["code"], "INCOMPLETE_EVIDENCE")
        self.assertIn("RESULTS.md", report["blocking_findings"][0]["details"])
        self.assertIn("tests/*", report["blocking_findings"][0]["details"])

    def test_changed_catalog_protocol_requires_corresponding_dossier(self):
        self.assertEqual(self.audit("cloud/web/lib/example-protocol.mjs")["blocking_findings"][0]["code"], "MISSING_CHANGED_CATALOG_DOSSIER")
        self.assertEqual(self.audit("cloud/web/lib/example-protocol.mjs", f"{self.app_path}/ANALYSIS.md")["blocking_findings"], [])

    def test_changed_shared_tool_requires_registry_and_snapshot(self):
        x = self.audit(self.toolpath)
        self.assertEqual(x["blocking_findings"][0]["code"], "TOOL_REGISTRY_UPDATE_REQUIRED")
        self.put(self.toolpath, "print('modified')\n")
        x = self.audit(self.toolpath, "analysis/platform/apk-tooling/tool_sources.v1.json")
        self.assertEqual(x["blocking_findings"][0]["code"], "TOOL_SOURCE_CHANGED")

    def test_document_only_change_does_not_require_evidence(self):
        self.assertEqual(self.audit("docs/cloud/README.md")["blocking_findings"], [])

    def test_noncanonical_paths_rejected(self):
        for path in ("../bad", "/absolute/path", "a/../../b", "a\\b"):
            self.assertFalse(mod.inside_repo_path(path))
        with self.assertRaises(ValueError):
            mod.changed_paths(self.root, None, ["../bad"])

    def test_malformed_manifest_rejected(self):
        self.put(f"{self.app_path}/MANIFEST.json", "not json")
        report = self.audit(f"{self.app_path}/MANIFEST.json")
        self.assertEqual(report["blocking_findings"][0]["code"], "INCOMPLETE_EVIDENCE")

    def test_package_mismatch_rejected(self):
        p = self.root / self.app_path / "MANIFEST.json"
        data = json.loads(p.read_text())
        data["package_name"] = "wrong.package"
        p.write_text(json.dumps(data))
        report = self.audit(f"{self.app_path}/MANIFEST.json")
        self.assertEqual(report["blocking_findings"][0]["code"], "INCOMPLETE_EVIDENCE")


if __name__ == "__main__":
    unittest.main()
