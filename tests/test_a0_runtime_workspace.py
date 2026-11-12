"""F7-A0-P03 workspace tests (host fixtures only; no real APK or decoders)."""
import hashlib
from pathlib import Path
import tempfile
import unittest

from cloud.apk_analysis.workspace import WorkspaceError, WorkspaceStore


class WorkspaceRetentionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "apk-analysis"
        self.store = WorkspaceStore(self.root)
        self.store.initialize()

    def test_only_job_residue_removed_after_result_persisted(self):
        cache_resource = self.store.cache / "jadx-verified.jar"
        cache_resource.write_bytes(b"persistent-jadx-placeholder")
        retained = self.root / "results"
        retained.mkdir(mode=0o700)
        result = retained / "report.json"
        result.write_text('{"synthetic":true}')
        job_id = self.store.create()
        job = self.store.jobs / job_id
        (job / "input" / "sample.apk").write_bytes(b"synthetic-fixture")
        (job / "scratch" / "temporary.dex").write_bytes(b"temporary")
        self.store.result_persisted(job_id, hashlib.sha256(result.read_bytes()).hexdigest(),
                                    "results/" + job_id)
        self.assertFalse(job.exists())
        self.assertEqual(cache_resource.read_bytes(), b"persistent-jadx-placeholder")
        self.assertTrue(result.exists())
        self.assertEqual(self.store._load(job_id)["status"], "WORKSPACE_PURGED")
        self.assertFalse(self.store.cleanup(job_id))

    def test_cannot_delete_ongoing_job(self):
        job_id = self.store.create()
        with self.assertRaises(WorkspaceError):
            self.store.cleanup(job_id)
        self.assertTrue((self.store.jobs / job_id).exists())

    def test_human_escalation_never_deleted_early(self):
        job_id = self.store.create()
        self.store.mark_awaiting_human(job_id)
        with self.assertRaises(WorkspaceError):
            self.store.cleanup(job_id)
        self.assertTrue((self.store.jobs / job_id).exists())
        self.store.close_without_result(job_id)
        self.assertFalse((self.store.jobs / job_id).exists())

    def test_reap_completed_only_after_crash(self):
        saved = self.store.create()
        active = self.store.create()
        self.store.result_persisted(saved, "a" * 64, "results/" + saved, cleanup=False)
        self.assertTrue((self.store.jobs / saved).exists())
        self.assertEqual(self.store.reap_completed(), [saved])
        self.assertFalse((self.store.jobs / saved).exists())
        self.assertTrue((self.store.jobs / active).exists())

    def test_invalid_job_ids_are_rejected(self):
        for value in ("../../", "example", "../" + "a" * 32, "/" + "a" * 32, "A" * 32):
            with self.subTest(value=value), self.assertRaises(WorkspaceError):
                self.store.cleanup(value)

    def test_symlinked_job_target_denied_without_following(self):
        job_id = self.store.create()
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        important = outside / "keep"
        important.write_text("private")
        job = self.store.jobs / job_id
        (job / ".spdecode-job").unlink()
        for child in ("input", "scratch", "output-staging"):
            (job / child).rmdir()
        job.rmdir()
        job.symlink_to(outside, target_is_directory=True)
        self.store.result_persisted(job_id, "b" * 64, "results/" + job_id, cleanup=False)
        with self.assertRaises(WorkspaceError):
            self.store.cleanup(job_id)
        self.assertEqual(important.read_text(), "private")

    def test_nested_symlink_is_not_followed_during_cleanup(self):
        job_id = self.store.create()
        outside = self.root / "other-private"
        outside.mkdir(mode=0o700)
        (outside / "keep").write_text("safe")
        (self.store.jobs / job_id / "scratch" / "link").symlink_to(outside, target_is_directory=True)
        self.store.result_persisted(job_id, "c" * 64, "results/" + job_id)
        self.assertEqual((outside / "keep").read_text(), "safe")

    def test_storage_root_cannot_be_symlink(self):
        link = self.root.parent / "link-to-root"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(WorkspaceError):
            WorkspaceStore(link)

    def test_invalid_digest_does_not_mark_finished(self):
        job_id = self.store.create()
        with self.assertRaises(WorkspaceError):
            self.store.result_persisted(job_id, "bad", "results/ref")
        self.assertEqual(self.store._load(job_id)["status"], "IN_PROGRESS")


if __name__ == "__main__":
    unittest.main()
