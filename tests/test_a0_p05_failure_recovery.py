"""P05 fault/recovery tests on first-party synthetic jobs (never external APKs).

The subprocess termination is real. Durable object-store authorization is
still an A4/A5 dependency and is intentionally represented by a test oracle.
"""
from __future__ import annotations

import errno
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from cloud.apk_analysis.checkpoint_journal import (
    CheckpointError, CheckpointJournal, checkpoint_record,
)
from cloud.apk_analysis.workspace import WorkspaceError, WorkspaceStore


class P05CrashRecoveryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.store = WorkspaceStore(self.root / "private-workspace")
        self.store.initialize()
        self.cache = self.store.cache / "verified-resource"
        self.cache.write_bytes(b"owned-cache-fixture")

    def start_job(self):
        job_id = self.store.create()
        path = self.store.jobs / job_id / "input" / "owned.apk"
        path.write_bytes(b"owned-synthetic-fixture")
        return job_id, path

    @unittest.skipUnless(sys.platform.startswith("linux"), "SIGKILL recovery is a Linux lab test")
    def test_real_worker_sigkill_preserves_incomplete_job_and_cache(self):
        job_id, uploaded = self.start_job()
        ready = self.store.jobs / job_id / "scratch" / "worker-started"
        code = (
            "import os, pathlib, sys, time\n"
            "p=pathlib.Path(sys.argv[1]);"
            "f=p.open('wb');f.write(b'working');f.flush();os.fsync(f.fileno());f.close();"
            "time.sleep(120)\n"
        )
        proc = subprocess.Popen([sys.executable, "-c", code, str(ready)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 8
            while not ready.exists() and proc.poll() is None and time.monotonic() < deadline:
                time.sleep(0.03)
            self.assertTrue(ready.exists(), "worker did not start")
            proc.kill()  # simulated abrupt container termination / OOM
            proc.wait(timeout=5)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
        restarted = WorkspaceStore(self.store.root)
        self.assertEqual(restarted.reap_completed(), [])
        self.assertTrue(uploaded.exists())
        self.assertEqual(restarted._load(job_id)["status"], "IN_PROGRESS")
        self.assertEqual(self.cache.read_bytes(), b"owned-cache-fixture")
        with self.assertRaises(WorkspaceError):
            restarted.cleanup(job_id)

    def test_disk_full_during_state_commit_does_not_purge_or_escalate(self):
        job_id, uploaded = self.start_job()
        with mock.patch("cloud.apk_analysis.workspace.os.replace",
                        side_effect=OSError(errno.ENOSPC, "synthetic disk full")):
            with self.assertRaises(OSError):
                self.store.mark_awaiting_human(job_id)
        restarted = WorkspaceStore(self.store.root)
        self.assertEqual(restarted._load(job_id)["status"], "IN_PROGRESS")
        self.assertEqual(restarted.reap_completed(), [])
        self.assertTrue(uploaded.exists())

    def test_human_case_survives_restarts_and_auto_reaper(self):
        job_id, uploaded = self.start_job()
        self.store.mark_awaiting_human(job_id)
        restarted = WorkspaceStore(self.store.root)
        self.assertEqual(restarted.reap_completed(), [])
        self.assertTrue(uploaded.exists())
        with self.assertRaises(WorkspaceError):
            restarted.cleanup(job_id)
        self.assertEqual(restarted._load(job_id)["status"], "AWAITING_HUMAN")

    def test_result_survives_restart_and_only_then_can_reap(self):
        job_id, uploaded = self.start_job()
        result_dir = self.root / "durable-test-only"
        result_dir.mkdir(mode=0o700)
        result = result_dir / "result"
        result.write_bytes(b"first-party-result")
        digest = hashlib.sha256(result.read_bytes()).hexdigest()
        reference = "obj:" + "d" * 32
        journal = CheckpointJournal(self.root / "checkpoints")
        journal.append_checkpoint(job_id, checkpoint_record(
            stage="REPORT", status="OK", evidence="OBSERVED", privacy="USER_PRIVATE",
            tool_id="owned-test", tool_sha256="a" * 64, input_sha256="b" * 64,
            artifact_ref=reference, artifact_sha256=digest,
            artifact_bytes=result.stat().st_size, error_code=None,
            verification_ref=None, authorization_ref=None,
        ))
        with self.assertRaises(CheckpointError):
            journal.finalize_result(job_id, verify_persisted=lambda *args: False)
        self.assertEqual(self.store.reap_completed(), [])
        self.assertTrue(uploaded.exists())
        restarted_journal = CheckpointJournal(self.root / "checkpoints")
        restarted_store = WorkspaceStore(self.store.root)

        # Test oracle only; real backend must also check tenant/authorization.
        def verified(ref, sha, size):
            return (ref == reference and sha == digest
                    and size == result.stat().st_size
                    and hashlib.sha256(result.read_bytes()).hexdigest() == digest)

        restarted_journal.finalize_result(job_id, verify_persisted=verified)
        sha, ref = restarted_journal.cleanup_receipt(job_id)
        restarted_store.result_persisted(job_id, sha, ref, cleanup=False)
        self.assertEqual(restarted_store.reap_completed(), [job_id])
        self.assertFalse(uploaded.exists())
        self.assertEqual(result.read_bytes(), b"first-party-result")
        self.assertEqual(self.cache.read_bytes(), b"owned-cache-fixture")
        self.assertEqual(restarted_store.reap_completed(), [])


if __name__ == "__main__":
    unittest.main()
