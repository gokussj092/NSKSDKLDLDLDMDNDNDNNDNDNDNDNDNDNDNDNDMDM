"""Regression for preserving large original icons and sampling their display only."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLOUD = ROOT / "android/app/src/main/java/com/ghostdeveloper/spdecode/cloud"


class ServerVpnIconPolicyTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("java"), "JDK required for production Java icon-policy execution")
    def test_production_policy_accepts_large_original_png_and_bounds_display_memory(self):
        with tempfile.TemporaryDirectory() as folder:
            result = subprocess.run([
                shutil.which("java"), str(ROOT / "tests/golden/ServerVpnIconPolicyHarness.java"),
                str(CLOUD / "ServerVpnIconPolicy.java"),
                str(ROOT / "cloud/web/public/server-vpn-icons/royal-tunnel.png"), folder,
            ], capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertIn(b"Original PNG accepted", result.stdout)

    def test_client_preserves_integrity_original_cache_and_general_transport_budget(self):
        source = (CLOUD / "ServerVpnCatalogRepository.kt").read_text()
        cache = (CLOUD / "ServerVpnSecureCache.kt").read_text()
        transport = (ROOT / "android/app/src/main/cpp/spdecode_transport.cpp").read_text()
        self.assertNotIn("maxIconBytes", source)
        self.assertNotIn("350_000", source)
        self.assertIn("ServerVpnIconPolicy.sampleSize", source)
        self.assertIn("ServerVpnIconPolicy.isPng(bytes)", source)
        self.assertIn("digest(bytes)!=checksum", source)
        self.assertIn('candidates.add("icon-$id" to bytes)', source)
        self.assertIn("ServerVpnIconPolicy.CACHE_RECORD_BYTES", cache)
        self.assertIn("kMaxReplyBytes = 6 * 1024 * 1024", transport)


if __name__ == "__main__":
    unittest.main()
