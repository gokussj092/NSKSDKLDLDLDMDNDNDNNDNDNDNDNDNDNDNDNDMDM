"""Cloud C8 Phase VI: consent, encrypted cache and manifest rollout contracts.

All tests are source/contract checks. Android Keystore cryptographic behavior
is additionally exercised by CloudCacheAndConsentTest on the emulator.
"""
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]
KOTLIN=ROOT/"android/app/src/main/java/com/ghostdeveloper/spdecode"
CLOUD=KOTLIN/"cloud"

def src(path):
    return path.read_text(encoding="utf-8")

class PhaseViPrivacySecurityTests(unittest.TestCase):
    def test_cloud_network_calls_cannot_bypass_legal_acceptance(self):
        client=src(CLOUD/"CloudDecodeClient.kt")
        self.assertIn('private fun requireLegalConsent()',client)
        self.assertIn('CloudLegalConsent.accepted(app)',client)
        self.assertIn('Failure("LEGAL_CONSENT_REQUIRED",403)',client)
        self.assertGreaterEqual(client.count("requireLegalConsent()"),4)
        self.assertRegex(client,r'private suspend fun decode\(.*?[\s\S]*?withContext\(Dispatchers.IO\) \{ requireLegalConsent\(\) \}')
        activity=src(KOTLIN/"MainActivity.kt")
        self.assertIn('private fun requireCloudLegal():Boolean',activity)
        for method in ("prepareSingleImport","decodeText","decodeCloud","decodeNurServers","decodeServerVpnProvider"):
            self.assertRegex(activity,rf'private fun {method}\(.*?\) \{{\s*if\(!requireCloudLegal\(\)')
        self.assertIn('if(!requireCloudLegal())return\n        require(privateCredentialId',activity)
        self.assertIn('onDecline={finishAffinity()}',activity)

    def test_no_plaintext_backup_and_key_generation_lock(self):
        cache=src(CLOUD/"ServerVpnSecureCache.kt")
        manifest=src(ROOT/"android/app/src/main/AndroidManifest.xml")
        self.assertIn('android:allowBackup="false"',manifest)
        self.assertIn('android:usesCleartextTraffic="false"',manifest)
        self.assertIn('noBackupFilesDir',cache)
        self.assertIn('AndroidKeyStore',cache)
        self.assertIn('setKeySize(256)',cache)
        self.assertIn('AES/GCM/NoPadding',cache)
        self.assertIn('cipher.updateAAD(',cache)
        self.assertIn('private val keyLock=Any()',cache)
        self.assertIn('synchronized(keyLock)',cache)
        self.assertIn('temporary.renameTo(destination)',cache)
        self.assertNotIn('SecretKeySpec(',cache)

    def test_icon_decode_blocks_decompression_bombs_before_pixels(self):
        repo=src(CLOUD/"ServerVpnCatalogRepository.kt")
        self.assertIn('inJustDecodeBounds=true',repo)
        self.assertIn('bounds.outWidth<=0',repo)
        self.assertIn('bounds.outHeight<=0',repo)
        self.assertIn('digest(bytes)!=checksum',repo)
        self.assertNotIn('maxIconBytes=256*1024',repo)
        self.assertNotIn('base64.length>350_000',repo)
        self.assertIn('ServerVpnIconPolicy.sampleSize',repo)
        self.assertIn('ServerVpnIconPolicy.isPng(bytes)',repo)
        self.assertIn('versionCheckMillis=15*60_000L',repo)
        self.assertIn('remote.optBoolean("unchanged",false)',repo)
        self.assertIn('vault.write("catalog",fresh.toString()',repo)

    def test_monotonic_self_hosted_catalog_versions(self):
        code=src(ROOT/"cloud/web/lib/server-vpn-catalog.mjs")
        compose=src(ROOT/"cloud/compose.yaml")
        route=src(ROOT/"cloud/web/app/api/v1/server-vpn/catalog/route.js")
        self.assertIn('activeCatalogVersion(env=process.env)',code)
        self.assertIn('number<11',code)
        self.assertIn('return Math.max(number,CATALOG_VERSION)',code)
        self.assertIn('CLOUD_SERVER_VPN_CATALOG_VERSION: ${CLOUD_SERVER_VPN_CATALOG_VERSION:-11}',compose)
        self.assertIn('const summary=await providerOverview(process.env,{syncCatalog:true})',route)
        self.assertIn('projectedCatalogVersion(request,summary.catalogVersion,policy):summary.catalogVersion',route)
        self.assertIn('input.knownVersion===currentVersion',route)
        self.assertIn('unchanged:true',route)

    def test_withdrawal_is_accessible_and_keeps_local_history(self):
        consent=src(CLOUD/"CloudLegalConsent.kt")
        self.assertIn('ServerVpnSecureCache(context).delete("legal")',consent)
        settings=src(KOTLIN/"FunctionalSettingsPanel.kt")
        self.assertIn('cloud_legal_withdraw_detail',settings)
        self.assertIn('onWithdrawConsent()',settings)
        source=src(KOTLIN/"MainActivity.kt")
        self.assertIn('CloudLegalConsent.revoke(this@MainActivity)',source)
        self.assertIn('cloudClient.clearSession()',source)
        self.assertIn('showCloudLegal=true',source)
        locales=("values","values-es","values-ar","values-de","values-fa",
                 "values-fr","values-in","values-pt-rBR","values-ru")
        from xml.etree import ElementTree
        for locale in locales:
            with self.subTest(locale=locale):
                p=ROOT/"android/app/src/main/res"/locale/"cloud_legal_strings.xml"
                keys={e.attrib["name"] for e in ElementTree.parse(p).getroot().findall("string")}
                self.assertTrue({"cloud_legal_withdraw",
                                 "cloud_legal_withdraw_detail"}<=keys)

    def test_android_test_verifies_tamper_and_nonce_rotation(self):
        source=src(ROOT/"android/app/src/androidTest/java/com/ghostdeveloper/spdecode/CloudCacheAndConsentTest.kt")
        for statement in ("roundTripHasUniqueNoncesAndNoPlaintextOnDisk",
                          "tamperingOrRenamingEncryptedRecordsFailsAuthentication",
                          "illegalIdentifiersAreRejected",
                          "consentIsEncryptedAndBoundToCurrentLegalVersion",
                          "withdrawalBlocksCloudWithoutErasingEncryptedCatalog"):
            self.assertIn(statement,source)
        self.assertIn('assertFalse(first.contentEquals(second))',source)
        self.assertIn('assertNull(vault.read(other))',source)

if __name__=="__main__":
    unittest.main()
