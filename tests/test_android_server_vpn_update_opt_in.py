"""Server VPN updates are opt-in, manually confirmed and use original icons."""
import re
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/"android/app/src/main/java/com/ghostdeveloper/spdecode"
WEB=ROOT/"cloud/web"

class ServerVpnUpdateOptInContracts(unittest.TestCase):
    def test_manual_probe_prompts_before_download_and_header_only_button(self):
        activity=(SRC/"MainActivity.kt").read_text("utf-8")
        ui=(SRC/"SpDecodeApp.kt").read_text("utf-8")
        self.assertIn("cloudClient.watchCatalogVersion(0)",activity)
        self.assertIn("pendingServerVpnCatalogVersion=remoteVersion",activity)
        self.assertIn("onConfirmServerVpnUpdate={confirmServerVpnUpdate()}",activity)
        self.assertIn("if(force || CloudCatalogUpdates.enabled(this@MainActivity))",activity)
        self.assertIn("refreshServerVpn(force=CloudCatalogUpdates.enabled(this))",activity)
        self.assertIn("R.string.server_vpn_catalog_update_question",ui)
        self.assertIn('testTag("server_vpn_manual_refresh")',ui)
        header=ui[ui.index("private fun BrandHeader("):ui.index("private fun HomeScreen(")]
        self.assertIn('testTag("server_vpn_manual_refresh")',header)
        screen=ui[ui.index("private fun ServerVpnScreen("):ui.index("private fun ServerVpnNewTag(")]
        self.assertNotIn('testTag("server_vpn_manual_refresh")',screen)

    def test_background_sync_is_optional_and_daily(self):
        code=(SRC/"cloud/CloudCatalogUpdates.kt").read_text("utf-8")
        self.assertIn("if(!enabled(context)||!CloudLegalConsent.accepted(context))return",code)
        self.assertIn("PeriodicWorkRequestBuilder<CloudCatalogSyncWorker>(24,TimeUnit.HOURS)",code)
        self.assertIn("ExistingPeriodicWorkPolicy.UPDATE",code)
        self.assertIn("wm.cancelUniqueWork(BACKUP)",code)
        self.assertIn("wm.cancelUniqueWork(PUSH_WORK_NAME)",code)

    def test_all_public_catalog_entries_have_paired_png_icons(self):
        catalog=(WEB/"lib/server-vpn-catalog.mjs").read_text("utf-8")
        ids=re.findall(r'\{id:"([a-z0-9-]+)", name:"[^"]+", icon:"([a-z0-9-]+\.png)"',catalog)
        # Every catalog provider must have a registered PNG. Do not hardcode a
        # historical provider count: new catalog integrations are expected.
        total_entries=len(re.findall(r'\{id:"[a-z0-9-]+"',catalog))
        self.assertGreater(total_entries,0)
        self.assertEqual(len(ids),total_entries)
        self.assertEqual(len({i for i,_ in ids}),len(ids))
        for provider,filename in ids:
            with self.subTest(provider=provider):
                raw=(WEB/"public/server-vpn-icons"/filename).read_bytes()
                self.assertTrue(raw.startswith(b"\x89PNG\r\n\x1a\n"))
                self.assertGreater(len(raw),32)

if __name__=="__main__":
    unittest.main()
