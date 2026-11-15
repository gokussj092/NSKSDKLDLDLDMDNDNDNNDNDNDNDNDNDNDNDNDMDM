"""Unit tests for pinned dependency provenance guard; no tools executed."""
import json, tempfile, unittest
from pathlib import Path
from scripts.ci.check_apk_tool_dependencies import check
class DependencyAuditTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name)
        self.p=self.root/"analysis/platform/apk-tooling/dependencies.v1.json";self.p.parent.mkdir(parents=True)
        self.q=self.root/"scripts/apk_analysis/requirements.txt";self.q.parent.mkdir(parents=True)
        self.q.write_text("Demo-Tool==1.2.3\n")
        self.data={"packages":[{"name":"Demo-Tool","version":"1.2.3","requirement":"Demo-Tool==1.2.3","license_evidence_url":"https://pypi.org/project/Demo-Tool/1.2.3/","source_distribution":{"filename":"demo-tool-1.2.3.tar.gz","sha256_reported_by_pypi":"a"*64,"checksum_scope":"REFERENCE_SDIST_NOT_INSTALLED_WHEEL"},"unattended_execution":"DISABLED"}],"p01_review":{"installed_artifact_hash_count":0,"automated_worker_approval":False}}
        self.save()
    def save(self):self.p.write_text(json.dumps(self.data))
    def test_ok(self):self.assertEqual(check(self.root)["pinned"],1)
    def test_drift(self):
        self.q.write_text("Demo-Tool==1.2.4\n")
        with self.assertRaises(ValueError):check(self.root)
    def test_unpinned_fails(self):
        self.q.write_text("Demo-Tool>=1.2.3\n")
        with self.assertRaises(ValueError):check(self.root)
    def test_wrong_hash_scope(self):
        self.data["packages"][0]["source_distribution"]["checksum_scope"]="INSTALLED_WHEEL";self.save()
        with self.assertRaises(ValueError):check(self.root)
    def test_no_auto_execution(self):
        self.data["packages"][0]["unattended_execution"]="ENABLED";self.save()
        with self.assertRaises(ValueError):check(self.root)
    def test_no_fake_install_attestation(self):
        self.data["p01_review"]["installed_artifact_hash_count"]=1;self.save()
        with self.assertRaises(ValueError):check(self.root)
if __name__=="__main__":unittest.main()
