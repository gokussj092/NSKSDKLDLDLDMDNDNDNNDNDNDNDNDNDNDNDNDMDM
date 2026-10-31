"""Play signed release signature, edge-to-edge and 16 KiB regression contracts."""
from __future__ import annotations

import struct
import re
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.android_16kb_elf_audit import audit_archive, verify_elf

ROOT = Path(__file__).resolve().parents[1]


def fake_elf64(alignment: int) -> bytes:
    binary = bytearray(128)
    binary[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", binary, 32, 64)
    struct.pack_into("<H", binary, 54, 56)
    struct.pack_into("<H", binary, 56, 1)
    struct.pack_into("<IIQQQQQQ", binary, 64, 1, 5, 0, 0, 0, 128, 128, alignment)
    return bytes(binary)


class AndroidPlayCompatibility(unittest.TestCase):
    def test_64bit_load_segment_alignment_accepts_16k_not_4k(self):
        self.assertEqual(verify_elf(fake_elf64(16384)), [16384])
        self.assertEqual(verify_elf(fake_elf64(65536)), [65536])
        with self.assertRaisesRegex(ValueError, "alignment fails"):
            verify_elf(fake_elf64(4096))
        with self.assertRaisesRegex(ValueError, "not an ELF"):
            verify_elf(b"\x00" * 128)

    def test_audit_rejects_bad_native_archive(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "test.aab"
            with zipfile.ZipFile(p, "w") as bundle:
                bundle.writestr("base/lib/arm64-v8a/libv7q3.so", fake_elf64(4096))
            with self.assertRaisesRegex(ValueError, "alignment fails"):
                audit_archive(p)
            with zipfile.ZipFile(p, "w") as bundle:
                bundle.writestr("base/lib/arm64-v8a/libv7q3.so", fake_elf64(16384))
            self.assertEqual(len(audit_archive(p)), 1)

    def test_edge_to_edge_generated_cloud_activity_and_safe_insets(self):
        gradle = (ROOT / "android/app/build.gradle.kts").read_text("utf-8")
        app = (ROOT / "android/app/src/main/java/com/ghostdeveloper/spdecode/SpDecodeApp.kt").read_text("utf-8")
        styles = (ROOT / "android/app/src/main/res/values/styles.xml").read_text("utf-8")
        self.assertIn('import androidx.activity.enableEdgeToEdge', gradle)
        self.assertIn('enableEdgeToEdge(', gradle)
        self.assertIn('SystemBarStyle.dark(android.graphics.Color.TRANSPARENT)', gradle)
        self.assertIn('window.decorView.systemUiVisibility=0', gradle)
        self.assertIn('Modifier.fillMaxSize().background(Background).safeDrawingPadding()', app)
        self.assertNotIn('name="android:statusBarColor"', styles)
        self.assertNotIn('name="android:navigationBarColor"', styles)

    def test_native_cmake_and_signed_build_audit(self):
        cmake = (ROOT / "android/app/src/main/cpp/CMakeLists.txt").read_text("utf-8")
        flow = (ROOT / ".github/workflows/play-beta-artifacts.yml").read_text("utf-8")
        for linker in ("max-page-size=16384", "common-page-size=16384"):
            self.assertIn(linker, cmake)
        self.assertIn("android_16kb_elf_audit.py", flow)
        self.assertIn('zipalign" -c -P 16', flow)
        gradle = (ROOT / "android/app/build.gradle.kts").read_text("utf-8")
        version = re.search(r'versionName\s*=\s*"([^"]+)"', gradle)
        code = re.search(r'versionCode\s*=\s*(\d+)', gradle)
        self.assertIsNotNone(version)
        self.assertIsNotNone(code)
        self.assertGreaterEqual(int(code.group(1)), 30)
        self.assertIn(f"versionName='{version.group(1)}'", flow)
        self.assertIn(f"versionCode='{code.group(1)}'", flow)

    def test_play_signing_certificate_is_mandatory(self):
        flow = (ROOT / ".github/workflows/play-beta-artifacts.yml").read_text("utf-8")
        self.assertIn("secrets.SPDECODE_PLAY_APP_SIGNER_SHA256", flow)
        self.assertIn("vars.SPDECODE_PLAY_APP_SIGNER_SHA256", flow)
        self.assertIn("64760393e52521294b40a1fd978b5bae732b7d8604bd222ca01166a25407854b", flow)
        self.assertIn('github.event.repository.private == true', flow)
        self.assertIn('::error::Play App Signing SHA-256', flow)


if __name__ == "__main__":
    unittest.main()
