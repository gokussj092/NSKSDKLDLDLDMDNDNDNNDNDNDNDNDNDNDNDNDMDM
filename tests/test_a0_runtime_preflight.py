"""F7-A0-P03 lightweight image preflight fixtures; no package installation."""
import hashlib
from pathlib import Path
from unittest import mock
import tempfile
import unittest

from cloud.apk_analysis import runtime_preflight as preflight


class ImagePreflightTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.req = self.root / "requirements.txt"
        self.req.write_text("Demo-Tool==1.2.3\n")
        self.jar = self.root / "jadx.jar"
        self.jar.write_bytes(b"verified synthetic resource")
        self.sha = hashlib.sha256(self.jar.read_bytes()).hexdigest()

    def preflight(self, *, cache=True, actual="1.2.3"):
        if not cache:
            self.jar.unlink(missing_ok=True)
        with mock.patch.object(preflight, "REQ", self.req), \
             mock.patch.object(preflight, "JADX", self.jar), \
             mock.patch.object(preflight, "JADX_SHA256", self.sha), \
             mock.patch.object(preflight.metadata, "version", return_value=actual), \
             mock.patch.object(preflight.subprocess, "run") as java:
            java.return_value.returncode = 0
            return preflight.check()

    def test_version_and_cached_jar_verified(self):
        self.assertEqual(self.preflight()["jadx_cache"], "HASH_VERIFIED")

    def test_version_drift_rejected_without_install(self):
        with self.assertRaises(ValueError):
            self.preflight(actual="1.2.4")

    def test_resource_missing_requires_preload(self):
        with self.assertRaises(ValueError):
            self.preflight(cache=False)

    def test_bad_resource_checksum_rejected(self):
        self.sha = "0" * 64
        with self.assertRaises(ValueError):
            self.preflight()

    def test_no_preload_allowed_only_in_explicit_diagnostic_mode(self):
        self.jar.unlink()
        with mock.patch.object(preflight, "REQ", self.req), \
             mock.patch.object(preflight, "JADX", self.jar), \
             mock.patch.object(preflight.metadata, "version", return_value="1.2.3"), \
             mock.patch.object(preflight.subprocess, "run") as java:
            java.return_value.returncode = 0
            self.assertEqual(preflight.check(allow_unprepared=True)["jadx_cache"], "NOT_PRELOADED")


if __name__ == "__main__":
    unittest.main()
