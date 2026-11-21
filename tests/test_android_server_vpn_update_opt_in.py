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
        self.assertIn("CloudCatalogUpdates.pendingVersion(this)",activity)
        self.assertIn("pendingServerVpnCatalogVersion=version",activity)
        self.assertIn("onConfirmServerVpnUpdate={confirmServerVpnUpdate()}",activity)
        confirmation=activity.split("private fun confirmServerVpnUpdate()",1)[1].split("private fun observeCatalogTransfer",1)[0]
        self.assertIn("CatalogTransferWorker.enqueue(this, version, automatic=false,",confirmation)
        self.assertNotIn("refreshIfDue(",activity)
        self.assertIn("probeUpdatesOnEntry()",activity)
        self.assertIn("refreshServerVpn()",activity)
        self.assertIn("confirmButton={Button(onClick=onConfirmServerVpnUpdate,",ui)
        self.assertIn("catalogTransfer?.let { transfer ->",ui)
        self.assertIn('testTag("server_vpn_manual_refresh")',ui)
        header=ui[ui.index("private fun BrandHeader("):ui.index("private fun HomeScreen(")]
        self.assertIn('testTag("server_vpn_manual_refresh")',header)
        screen=ui[ui.index("private fun ServerVpnScreen("):ui.index("private fun ServerVpnNewTag(")]
        self.assertNotIn('testTag("server_vpn_manual_refresh")',screen)

    def test_background_sync_is_optional_and_daily(self):
        code=(SRC/"cloud/CloudCatalogUpdates.kt").read_text("utf-8")
        self.assertIn("if(!enabled(context)||!CloudLegalConsent.accepted(context))return",code)
        self.assertIn("PeriodicWorkRequestBuilder<CloudCatalogSyncWorker>(24,TimeUnit.HOURS)",code)
        self.assertIn("watchCatalogVersion(0)",code)
        self.assertNotIn("repository.refreshIfDue(announcedVersion=requested)",code)
        self.assertIn("ExistingPeriodicWorkPolicy.KEEP",code)
        self.assertIn("wm.cancelUniqueWork(BACKUP)",code)
        self.assertIn("WorkManager.getInstance(context).cancelUniqueWork(PUSH_WORK_NAME)",code)
        self.assertIn("enabled(context) && backgroundEnabled(context)",code)
        self.assertIn('getBoolean(DOWNLOAD, false)',code)
        self.assertIn("!CloudLegalConsent.accepted(context)) return",code)
        self.assertIn("cancelAllWorkByTag(CatalogTransferWorker.AUTO_TAG)",code)

    def test_download_is_unique_and_progress_is_observed_by_the_activity(self):
        worker=(SRC/"cloud/CatalogTransferWorker.kt").read_text("utf-8")
        activity=(SRC/"MainActivity.kt").read_text("utf-8")
        repo=(SRC/"cloud/ServerVpnCatalogRepository.kt").read_text("utf-8")
        self.assertIn("enqueueUniqueWork(WORK_NAME, ExistingWorkPolicy.KEEP, request)",worker)
        self.assertIn("setRequiredNetworkType(NetworkType.CONNECTED)",worker)
        self.assertIn("createCancelPendingIntent(id)",worker)
        self.assertIn("useChunks = resumable",worker)
        self.assertIn("getWorkInfosForUniqueWorkLiveData",activity)
        self.assertIn("CatalogTransferWorker.BACKGROUND_TAG in active.tags",activity)
        self.assertIn("if (!CloudLegalConsent.accepted(app)) throw CancellationException",repo)
        manifest=(ROOT/"android/app/src/cloud/AndroidManifest.xml").read_text("utf-8")
        self.assertIn('android:screenOrientation="fullUser"',manifest)
        self.assertIn('android:configChanges="orientation|screenSize|screenLayout|keyboardHidden"',manifest)
        self.assertIn('android:foregroundServiceType="dataSync"',manifest)

    def test_all_public_catalog_entries_have_paired_png_icons(self):
        catalog=(WEB/"lib/server-vpn-catalog.mjs").read_text("utf-8")
        ids=re.findall(r'\{id:"([a-z0-9-]+)",\s*name:"[^"]+",\s*icon:"([a-z0-9-]+\.png)"',catalog)
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
