"""F7 offsite backup envelope: offline synthetic files only, never production env."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "scripts/backups/f7_offsite_envelope.py"
SPEC = importlib.util.spec_from_file_location("f7_offsite_envelope", SOURCE)
backup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backup)


class OffsiteEnvelopeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.private = self.root / "recovery-private.pem"
        self.public = self.root / "recipient-public.pem"
        backup.generate_recovery_keys(self.private, self.public)
        self.source = self.root / "synthetic-dump.bin"
        self.source.write_bytes(b"test-record-not-real-secret\n" * 30000)
        self.blob = self.root / "backup.enc"
        self.restored = self.root / "restored.bin"

    def seal(self, destination=None):
        return backup.seal(self.source, destination or self.blob,
                           self.public.read_bytes())

    def restore(self, destination=None, source=None, private=None):
        backup.unseal(source or self.blob, destination or self.restored,
                      (private or self.private).read_bytes())

    def test_large_streamed_dump_roundtrip(self):
        digest = self.seal()
        self.assertEqual(len(digest), 64)
        self.assertNotIn(b"test-record-not-real-secret", self.blob.read_bytes())
        self.restore()
        self.assertEqual(self.restored.read_bytes(), self.source.read_bytes())
        self.assertEqual(self.restored.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.blob.stat().st_mode & 0o777, 0o600)

    def test_wrong_key_never_publishes_plaintext(self):
        self.seal()
        alt_private = self.root / "alt-private.pem"
        alt_public = self.root / "alt-public.pem"
        backup.generate_recovery_keys(alt_private, alt_public)
        with self.assertRaises(Exception):
            self.restore(private=alt_private)
        self.assertFalse(self.restored.exists())

    def test_tampered_tag_fails_closed(self):
        self.seal()
        raw = bytearray(self.blob.read_bytes())
        raw[-1] ^= 1
        self.blob.write_bytes(raw)
        with self.assertRaises(Exception):
            self.restore()
        self.assertFalse(self.restored.exists())

    def test_tampered_ciphertext_fails_closed(self):
        self.seal()
        raw = bytearray(self.blob.read_bytes())
        raw[backup.HEADER_LEN + 43] ^= 1
        self.blob.write_bytes(raw)
        with self.assertRaises(Exception):
            self.restore()
        self.assertFalse(self.restored.exists())

    def test_tampered_header_fails_closed(self):
        self.seal()
        raw = bytearray(self.blob.read_bytes())
        raw[0] ^= 1
        self.blob.write_bytes(raw)
        with self.assertRaises(Exception):
            self.restore()
        self.assertFalse(self.restored.exists())

    def test_truncated_snapshot_rejected(self):
        self.seal()
        self.blob.write_bytes(self.blob.read_bytes()[:20])
        with self.assertRaises(backup.BackupError):
            self.restore()
        self.assertFalse(self.restored.exists())

    def test_snapshot_encryption_is_nondeterministic(self):
        first = self.seal()
        second_path = self.root / "backup-two.enc"
        second = self.seal(second_path)
        self.assertNotEqual(first, second)
        self.assertNotEqual(self.blob.read_bytes(), second_path.read_bytes())

    def test_immutable_output_cannot_be_overwritten(self):
        self.seal()
        with self.assertRaises(backup.BackupError):
            self.seal()
        self.restored.write_text("do not replace", "utf-8")
        with self.assertRaises(backup.BackupError):
            self.restore()
        self.assertEqual(self.restored.read_text("utf-8"), "do not replace")

    def test_reject_recipient_private_key_as_seal_public_key(self):
        with self.assertRaises((TypeError, ValueError)):
            backup.seal(self.source, self.blob, self.private.read_bytes())
        self.assertFalse(self.blob.exists())

    def test_recovery_key_files_never_overwritten(self):
        content = self.private.read_bytes()
        with self.assertRaises(backup.BackupError):
            backup.generate_recovery_keys(self.private, self.public)
        self.assertEqual(self.private.read_bytes(), content)

    def test_symlink_input_rejected(self):
        link = self.root / "link"
        link.symlink_to(self.source)
        with self.assertRaises(backup.BackupError):
            backup.seal(link, self.blob, self.public.read_bytes())

    def test_zero_byte_dump_roundtrip(self):
        self.source.write_bytes(b"")
        self.seal()
        self.restore()
        self.assertEqual(self.restored.read_bytes(), b"")


if __name__ == "__main__":
    unittest.main()
