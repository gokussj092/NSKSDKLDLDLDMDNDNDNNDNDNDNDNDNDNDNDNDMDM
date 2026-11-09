"""Synthetic-only safety regression; not a real 4.3.2 download test."""
import io
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

TARGET = Path(__file__).resolve().parents[1] / "tools" / "acquire.py"
spec = importlib.util.spec_from_file_location("tunneldoom_acquire", TARGET)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def archive(package="com.tunneldoom.http", version="4.3.2", code=432):
    content = io.BytesIO()
    with zipfile.ZipFile(content, "w") as z:
        z.writestr("manifest.json", json.dumps({
            "package_name": package, "version_name": version, "version_code": code}))
        z.writestr("com.tunneldoom.http.apk", b"synthetic fixture")
    return content.getvalue()


class AcquireTests(unittest.TestCase):
    def test_expected_metadata(self):
        result = mod.analyze_bytes(archive())
        self.assertEqual(result["versionCode"], 432)
        self.assertIn("signer_unverified", result["status"])

    def test_stale_version_rejected(self):
        with self.assertRaisesRegex(mod.AcquireError, "UNEXPECTED_VERSION"):
            mod.analyze_bytes(archive(version="4.3.0", code=430))

    def test_unrelated_package_rejected(self):
        with self.assertRaisesRegex(mod.AcquireError, "UNEXPECTED_PACKAGE"):
            mod.analyze_bytes(archive(package="invalid.example"))

    def test_url_allowlist(self):
        for url in ["http://d.apkpure.net/file", "https://evil.test/file",
                    "https://apkpure.net.evil.test/file", "file:///etc/passwd"]:
            with self.subTest(url=url), self.assertRaises(mod.AcquireError):
                mod.vetted_url(url)

    def test_exact_distribution_cdn_allowed(self):
        self.assertEqual(mod.vetted_url("https://data.winudf.com/release.xapk"),
                         "https://data.winudf.com/release.xapk")
        with self.assertRaises(mod.AcquireError):
            mod.vetted_url("https://data.winudf.com.evil.test/release.xapk")

    def test_redirect_rejects_non_allowlisted_host(self):
        with self.assertRaises(mod.AcquireError):
            mod.SafeRedirects().redirect_request(
                None, None, 302, "Found", {}, "https://evil.test/file")

    def test_private_write_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "original.xapk"
            mod.save_private(archive(), path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                mod.save_private(archive(), path)

    def test_corrupted_zip_rejected(self):
        with self.assertRaisesRegex(mod.AcquireError, "INVALID_XAPK"):
            mod.analyze_bytes(b"not a ZIP")


if __name__ == "__main__":
    unittest.main()
