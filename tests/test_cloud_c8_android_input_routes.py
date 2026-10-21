"""Protect Android Cloud input routing against regressions in the C8 server bridges."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANDROID = ROOT / "android/app/src/main/java/com/ghostdeveloper/spdecode"
WORKER = ROOT / "cloud/workers/python"

class CloudC8ClientRouting(unittest.TestCase):
    def test_cloud_file_extensions_match_real_worker_routes(self):
        client = (ANDROID / "cloud/CloudFileFormats.kt").read_text("utf-8")
        backend = (WORKER / "engine.py").read_text("utf-8")
        routes = {
            "mtp": ("My Tunnel Proxy", "My_Tunnel_Proxy/file_decoder.py"),
            "roy": ("Royal Tunnel VPN 7.0", "Royal_Tunnel_VPN/file_decoder.py"),
            "actun": ("AC TUNNEL VPN 1.4", "AC_TUNNEL_VPN/file_decoder.py"),
            "4ulite": ("4U TUNNEL LITE 2.2", "4U_TUNNEL_LITE/file_decoder.py"),
        }
        for suffix, (label, path) in routes.items():
            with self.subTest(suffix=suffix):
                self.assertIn(f'"{suffix}" to "{label}"', client)
                self.assertIn(f'"{suffix}": ("decoders/Python/apps/{path}"', backend)
        self.assertIn('"hxt" to "HX Tunnel VPN"', client)
        self.assertIn('basename.endsWith(".$it")', client)

    def test_cloud_text_vendor_prefixes_are_explicit_and_keep_content(self):
        client = (ANDROID / "cloud/CloudTextFormats.kt").read_text("utf-8")
        bridge = (WORKER / "text_bridge.py").read_text("utf-8")
        for scheme, suffix, app in (
            ("mytunnelproxy", "mtp", "My Tunnel Proxy"),
            ("actunnelvpn", "actun", "AC TUNNEL VPN"),
        ):
            with self.subTest(scheme=scheme):
                self.assertIn(f'value.startsWith("{scheme}://",ignoreCase=true)', client)
                self.assertIn(f'value.length>"{scheme}://".length', client)
                self.assertIn(f'TextProtocolDecoder.Input("{scheme}","{app}","{suffix}",value)', client)
                self.assertIn(f'"{scheme}://"', bridge)
        activity = (ANDROID / "MainActivity.kt").read_text("utf-8")
        self.assertIn('CloudTextFormats.identify(userText) else null', activity)
        self.assertIn('cloudClient.decodeText(userText,password)', activity)
        self.assertIn('CloudFileFormats.detect(name) else null', activity)
        self.assertIn('cloudClient.decodeFile(supported.suffix,input', activity)
        self.assertIn('BuildConfig.SPDECODE_CLOUD_ENABLED', activity)
        # The Android 239-format native catalog is deliberately not extended.
        frozen = (ANDROID / "parity/AndroidDecoderCatalog.kt").read_text("utf-8")
        self.assertIn("const val TOTAL_SUFFIXES = 239", frozen)

    def test_device_regression_suite_covers_case_and_legacy(self):
        suite = (ROOT / "android/app/src/androidTest/java/com/ghostdeveloper/spdecode/CloudC8InputRoutesTest.kt").read_text("utf-8")
        for symbol in ("test.mtp", "royal.ROY", "export.ACTUN", "profile.4ULITE",
                       "mytunnelproxy://cipher", "ACTUNNELVPN://cipher",
                       "historicalCloudLinksAreUnaffected"):
            self.assertIn(symbol, suite)

if __name__ == "__main__":
    unittest.main()
