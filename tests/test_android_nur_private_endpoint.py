"""Regression checks for private NUR Tunnel endpoint and HTTP Custom text contrast."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
ANDROID = ROOT / "android/app/src/main/java/com/ghostdeveloper/spdecode"
ASSET = ROOT / "android/app/src/main/assets/nur_tunnel_server_endpoint.json"


class NurEndpointPrivacyTest(unittest.TestCase):
    def test_endpoint_is_not_embedded_as_a_kotlin_literal(self):
        for name in ("NurTunnelServerCatalog.kt", "SpDecodeApp.kt", "MainActivity.kt"):
            source = (ANDROID / name).read_text("utf-8")
            self.assertNotIn("strongteam.co", source)
        self.assertIn("strongteam.co", ASSET.read_text("utf-8"))

    def test_endpoint_uses_existing_authenticated_asset_vault(self):
        catalog = (ANDROID / "NurTunnelServerCatalog.kt").read_text("utf-8")
        vault = (ANDROID / "parity/SecureAssetVault.kt").read_text("utf-8")
        gradle = (ROOT / "android/app/build.gradle.kts").read_text("utf-8")
        audit = (ROOT / "scripts/android_s_vault_audit.py").read_text("utf-8")
        for source in (vault, gradle, audit):
            self.assertIn("nur_tunnel_server_endpoint.json", source)
        self.assertIn('SecureAssetVault.readText(context, "nur_tunnel_server_endpoint.json")', catalog)
        self.assertNotIn('const val DEFAULT_URL = "https://', catalog)

    def test_server_vpn_screen_only_exposes_decode_action(self):
        source = (ANDROID / "SpDecodeApp.kt").read_text("utf-8")
        start = source.index("private fun ServerVpnScreen(")
        end = source.index("@Composable\nprivate fun CardText", start)
        screen = source[start:end]
        # A provider search is expected; only raw catalog URLs remain prohibited.
        self.assertIn("OutlinedTextField", screen)
        self.assertNotIn("nur_servers_catalog_url", screen)
        self.assertNotIn("var url", screen)
        self.assertIn("Button(onClick=onDecodeCatalog", screen)
        self.assertIn("enabled=!busy", screen)

    def test_http_custom_secret_fields_force_white_entry_text(self):
        source = (ANDROID / "HcProtectedImportDialog.kt").read_text("utf-8")
        self.assertEqual(source.count("textStyle=TextStyle(color=Color(0xFFF7F7F7))"), 2)
        gradle = (ROOT / "android/app/build.gradle.kts").read_text("utf-8")
        self.assertIn('versionName = "1.1.17"', gradle)
        self.assertIn("versionCode = 28", gradle)


if __name__ == "__main__":
    unittest.main()
