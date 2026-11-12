"""F7-A0-P04 deterministic tests: synthetic metadata only, no APK or network."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import threading
import unittest

from cloud.apk_analysis.checkpoint_journal import (
    CheckpointError, CheckpointJournal, checkpoint_record, ZERO,
)
from cloud.apk_analysis.workspace import WorkspaceStore


JOB = "a" * 32
SHA = "b" * 64
INPUT = "c" * 64
ARTIFACT = "obj:" + "d" * 32
PROOF = "proof:" + "e" * 32
AUTH = "auth:" + "f" * 32


class CheckpointJournalTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.journal = CheckpointJournal(self.root / "checkpoints")

    def record(self, **values):
        fields = dict(stage="STATIC_INVENTORY", status="OK",
                      evidence="OBSERVED", privacy="USER_PRIVATE",
                      tool_id="inspect-apk-static", tool_sha256=SHA,
                      input_sha256=INPUT, artifact_ref=ARTIFACT,
                      artifact_sha256="0" * 64, artifact_bytes=30,
                      error_code=None, verification_ref=None,
                      authorization_ref=None)
        fields.update(values)
        return checkpoint_record(**fields)

    def report(self):
        return self.journal.append_checkpoint(
            JOB, self.record(stage="REPORT", tool_id="report-store")
        )

    def test_append_only_hash_chain_and_recovery(self):
        first = self.journal.append_checkpoint(JOB, self.record())
        journal = CheckpointJournal(self.root / "checkpoints")
        result = journal.append_checkpoint(
            JOB, self.record(stage="RESOURCES", status="PARTIAL",
                             evidence="INFERRED")
        )
        self.assertEqual(result["sequence"], 2)
        self.assertEqual(result["previous_sha256"], first["event_sha256"])
        data = journal.inspect(JOB)
        self.assertEqual(data["sequence"], 2)
        self.assertFalse(data["final"])
        self.assertEqual(data["events"][0]["event_sha256"], first["event_sha256"])

    def test_finalization_requires_report_checkpoint(self):
        self.journal.append_checkpoint(JOB, self.record())
        with self.assertRaises(CheckpointError):
            self.journal.finalize_result(JOB, verify_persisted=lambda *args: True)

    def test_durable_result_verification_must_pass(self):
        self.report()
        with self.assertRaises(CheckpointError):
            self.journal.finalize_result(JOB, verify_persisted=lambda *args: False)
        self.assertEqual(self.journal.inspect(JOB)["sequence"], 1)

    def test_final_receipt_idempotent_and_blocks_new_checkpoint(self):
        self.report()
        verified = []
        def verifier(ref, digest, length):
            verified.append((ref, digest, length))
            return ref == ARTIFACT and digest == "0" * 64 and length == 30
        final = self.journal.finalize_result(JOB, verify_persisted=verifier)
        self.assertEqual(final["event_type"], "RESULT_COMMITTED")
        self.assertEqual(self.journal.finalize_result(JOB, verify_persisted=verifier), final)
        self.assertEqual(len(verified), 1)
        self.assertTrue(self.journal.inspect(JOB)["final"])
        self.assertEqual(self.journal.cleanup_receipt(JOB), ("0" * 64, ARTIFACT))
        with self.assertRaises(CheckpointError):
            self.journal.append_checkpoint(JOB, self.record(stage="REPORT"))

    def test_no_cleanup_receipt_without_finalization(self):
        self.report()
        with self.assertRaises(CheckpointError):
            self.journal.cleanup_receipt(JOB)

    def test_tampered_event_rejected(self):
        self.journal.append_checkpoint(JOB, self.record())
        file = self.root / "checkpoints" / JOB / "00000001.json"
        data = json.loads(file.read_text())
        data["record"]["stage"] = "DEX"
        file.write_text(json.dumps(data))
        with self.assertRaises(CheckpointError):
            self.journal.inspect(JOB)

    def test_gap_in_chain_fails_closed(self):
        self.journal.append_checkpoint(JOB, self.record())
        self.journal.append_checkpoint(JOB, self.record(stage="RESOURCES"))
        path = self.root / "checkpoints" / JOB / "00000001.json"
        path.unlink()
        with self.assertRaises(CheckpointError):
            self.journal.inspect(JOB)

    def test_unexpected_file_in_journal_rejected(self):
        self.journal.append_checkpoint(JOB, self.record())
        (self.root / "checkpoints" / JOB / "untrusted.json").write_text("{}")
        with self.assertRaises(CheckpointError):
            self.journal.inspect(JOB)

    def test_checkpoint_is_metadata_only_no_payload_or_credentials(self):
        with self.assertRaises(CheckpointError):
            self.journal.append_checkpoint(
                JOB, dict(self.record(), raw_payload="secret-material")
            )
        with self.assertRaises(CheckpointError):
            self.record(tool_id="https://private.example/vpn")
        with self.assertRaises(CheckpointError):
            self.record(artifact_ref="../private.apk")
        with self.assertRaises(CheckpointError):
            self.record(privacy="PUBLIC")
        with self.assertRaises(CheckpointError):
            self.record(artifact_bytes=True)

    def test_verified_real_requires_independent_proof_and_authorization(self):
        with self.assertRaises(CheckpointError):
            self.record(evidence="VERIFIED_REAL", verification_ref=PROOF)
        with self.assertRaises(CheckpointError):
            self.record(evidence="VERIFIED_SYNTHETIC")
        accepted = self.record(evidence="VERIFIED_REAL",
                               verification_ref=PROOF, authorization_ref=AUTH)
        self.assertEqual(accepted["evidence"], "VERIFIED_REAL")

    def test_failure_and_human_need_reason_codes(self):
        for status in ("FAILED", "NEEDS_HUMAN"):
            with self.subTest(status=status), self.assertRaises(CheckpointError):
                self.record(status=status, artifact_ref=None,
                            artifact_sha256=None, artifact_bytes=0)
        item = self.record(status="NEEDS_HUMAN", artifact_ref=None,
                           artifact_sha256=None, artifact_bytes=0,
                           error_code="EVIDENCE_INCOMPLETE")
        self.journal.append_checkpoint(JOB, item)
        self.assertFalse(self.journal.inspect(JOB)["final"])

    def test_stage_order_regression_rejected(self):
        self.journal.append_checkpoint(JOB, self.record(stage="DEX"))
        with self.assertRaises(CheckpointError):
            self.journal.append_checkpoint(JOB, self.record(stage="STATIC_INVENTORY"))

    def test_incomplete_atomic_write_is_not_a_committed_checkpoint(self):
        self.journal.append_checkpoint(JOB, self.record())
        directory = self.root / "checkpoints" / JOB
        (directory / ".event-uncommitted").write_bytes(b'{"partial":true')
        self.assertEqual(self.journal.inspect(JOB)["sequence"], 1)
        self.journal.append_checkpoint(JOB, self.record(stage="RESOURCES"))
        self.assertEqual(self.journal.inspect(JOB)["sequence"], 2)

    def test_recovery_ignores_orphan_without_silently_finishing(self):
        self.journal.append_checkpoint(JOB, self.record(stage="RESOURCES"))
        fresh = CheckpointJournal(self.root / "checkpoints")
        self.assertFalse(fresh.inspect(JOB)["final"])
        fresh.append_checkpoint(JOB, self.record(stage="DEX", status="FAILED",
                     evidence="UNKNOWN", error_code="TOOL_CRASH",
                     artifact_ref=None, artifact_sha256=None, artifact_bytes=0))
        self.assertEqual(fresh.inspect(JOB)["sequence"], 2)

    def test_public_progress_omits_internal_object_refs_and_hashes(self):
        self.report()
        progress = self.journal.user_progress(JOB)
        serialized = json.dumps(progress)
        self.assertNotIn(ARTIFACT, serialized)
        self.assertNotIn(SHA, serialized)
        self.assertNotIn(INPUT, serialized)
        self.assertNotIn("tool_id", serialized)
        self.assertEqual(progress["steps"][0]["stage"], "REPORT")

    def test_workspace_cleanup_only_after_successful_final_receipt(self):
        work = WorkspaceStore(self.root / "workspace")
        job_id = work.create(JOB)
        (work.jobs / job_id / "input" / "uploaded.apk").write_bytes(b"fixture APK only")
        cache = work.cache / "verified-tool"
        cache.write_bytes(b"cached resource")
        self.report()
        with self.assertRaises(CheckpointError):
            self.journal.cleanup_receipt(JOB)
        self.assertTrue((work.jobs / job_id).exists())
        self.journal.finalize_result(JOB, verify_persisted=lambda *args: True)
        sha, ref = self.journal.cleanup_receipt(JOB)
        # A5 will independently verify the external object and account again.
        work.result_persisted(JOB, sha, ref)
        self.assertFalse((work.jobs / job_id).exists())
        self.assertEqual(cache.read_bytes(), b"cached resource")

    def test_invalid_job_id_rejected(self):
        for invalid in ("../../etc", "B" * 32, "../" + JOB, "not-a-uuid"):
            with self.subTest(invalid=invalid), self.assertRaises(CheckpointError):
                self.journal.inspect(invalid)

    def test_parallel_writers_preserve_sequential_chain(self):
        # flock serializes different file-descriptor holders even in threads.
        failures = []
        def add():
            try:
                self.journal.append_checkpoint(JOB, self.record())
            except Exception as exc:
                failures.append(exc)
        threads = [threading.Thread(target=add) for _ in range(8)]
        for worker in threads: worker.start()
        for worker in threads: worker.join()
        self.assertFalse(failures)
        self.assertEqual(self.journal.inspect(JOB)["sequence"], 8)

    def test_invalid_final_storage_verifier_return_rejected(self):
        self.report()
        with self.assertRaises(CheckpointError):
            self.journal.finalize_result(JOB, verify_persisted=lambda *args: 1)

    def test_duplicate_json_key_rejected(self):
        self.journal.append_checkpoint(JOB, self.record())
        path = self.root / "checkpoints" / JOB / "00000001.json"
        body = path.read_text()
        path.write_text(body.replace('"event_type":', '"event_type":"CHECKPOINT","event_type":', 1))
        with self.assertRaises(CheckpointError):
            self.journal.inspect(JOB)


if __name__ == "__main__":
    unittest.main()
