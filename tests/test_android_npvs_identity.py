"""Cloud NPV identity wiring, frozen UI and privacy regression guards."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/"android/app"
SOURCE=APP/"src/main/java/com/ghostdeveloper/spdecode/cloud"


class AndroidNpvIdentityTests(unittest.TestCase):
    def test_only_generated_cloud_settings_get_the_new_section(self):
        gradle=(APP/"build.gradle.kts").read_text()
        self.assertIn('"        com.ghostdeveloper.spdecode.cloud.NpvsIdentitySettings()\\n" + anchor',gradle)
        settings=(SOURCE.parent/"FunctionalSettingsPanel.kt").read_text()
        self.assertNotIn("NpvsIdentitySettings",settings)
        self.assertIn('dependsOn(prepareQaSettingsSource)',gradle)

    def test_identity_store_and_picker_never_use_history_or_secret_intents(self):
        vault=(SOURCE/"NpvsIdentityVault.kt").read_text()
        for marker in ("noBackupFilesDir","AES/GCM/NoPadding","AndroidKeyStore","AtomicFile",
                       'fingerprint in fingerprints','fileSha256',"PKCS8EncodedKeySpec","sign.verify(signature)"):
            self.assertIn(marker,vault)
        picker=(SOURCE/"NpvsRecipientActivity.kt").read_text()
        self.assertIn('putExtra("ticket",ticket)',picker)
        self.assertIn("vault.matching(bytes)",picker)
        self.assertIn("FLAG_SECURE",picker)
        for forbidden in ("HistoryRepository","Telemetry","Log.","println(","privateKey\",",'putExtra("identity"'):
            self.assertNotIn(forbidden,vault+picker)
        manifest=(APP/"src/main/AndroidManifest.xml").read_text()
        self.assertIn('android:name=".cloud.NpvsRecipientActivity"\n            android:exported="false"',manifest)

    def test_copy_requires_explicit_action_and_generation_uses_api(self):
        ui=(SOURCE/"NpvsIdentitySettings.kt").read_text()
        for marker in ("client.generateNpvsIdentity()","SecureFlagPolicy.SecureOn",
                       "IS_SENSITIVE","npv_copy_private","npv_import","vault.enable(value)"):
            self.assertIn(marker,ui)
        client=(SOURCE/"CloudDecodeClient.kt").read_text()
        self.assertIn('NpvsRecipientActivity.choose(app,bytes)',client)
        self.assertIn('put("recipientKey",recipient)',client)
        self.assertIn('CloudNativeTransport.post("/api/v1/npvs/identity"',client)
        self.assertNotIn('lastDiagnostic=Diagnostic("identity"',client)


if __name__=="__main__":unittest.main()
