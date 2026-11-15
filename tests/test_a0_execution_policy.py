"""F7-A0-P03 policy negatives: no APK processing or Docker build."""
import json
from pathlib import Path
import tempfile
import unittest
from scripts.ci.check_apk_analysis_policy import check, PolicyError, POLICY_PATH


ROOT = Path(__file__).resolve().parents[1]


class ExecutionPolicyTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for relative in (
            "analysis/platform/apk-tooling/execution_policy.v1.json",
            "analysis/platform/apk-tooling/tool_sources.v1.json",
            "cloud/apk_analysis/compose.yaml",
            "cloud/apk_analysis/Dockerfile",
            "cloud/apk_analysis/Dockerfile.dockerignore",
            "scripts/apk_analysis/inspect_apk.py",
            "scripts/apk_analysis/decompile.py",
        ):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / relative).read_bytes())
        self.path = self.root / POLICY_PATH
        self.policy = json.loads(self.path.read_text())

    def save(self):
        self.path.write_text(json.dumps(self.policy))

    def test_repo_current_policy_valid_without_running_tools(self):
        result = check(ROOT)
        self.assertEqual(result["automatically_approved"], 0)
        self.assertGreater(result["reviewed_candidates"], 0)

    def test_disallow_automatic_execution(self):
        self.policy["profiles"][0]["auto_run"] = True
        self.save()
        with self.assertRaises(PolicyError):
            check(self.root)

    def test_disallow_privileged_network_access(self):
        self.policy["runtime"]["network_mode"] = "bridge"
        self.save()
        with self.assertRaises(PolicyError):
            check(self.root)

    def test_disallow_modified_tool_hash(self):
        self.policy["profiles"][0]["git_blob_sha1"] = "f" * 40
        self.save()
        with self.assertRaises(PolicyError):
            check(self.root)

    def test_no_unreviewed_broad_profile_approval(self):
        self.policy["profiles"][0]["approval"] = "APPROVED"
        self.save()
        with self.assertRaises(PolicyError):
            check(self.root)

    def test_results_persistence_must_precede_cleanup(self):
        self.policy["storage"]["job_lifecycle"] = "DELETE_AFTER_ANALYSIS"
        self.save()
        with self.assertRaises(PolicyError):
            check(self.root)

    def test_compose_must_not_mount_docker_socket(self):
        path = self.root / "cloud/apk_analysis/compose.yaml"
        path.write_text(path.read_text() + "\n# /var/run/docker.sock\n")
        with self.assertRaises(PolicyError):
            check(self.root)


if __name__ == "__main__":
    unittest.main()
