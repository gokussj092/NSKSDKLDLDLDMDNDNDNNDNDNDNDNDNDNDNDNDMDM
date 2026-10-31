"""Cloud NPV identity wiring, frozen UI and privacy regression guards."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/"android/app"
SOURCE=APP/"src/main/java/com/ghostdeveloper/spdecode/cloud"


class AndroidNpvIdentityTests(unittest.TestCase):
    def test_only_generated_cloud_settings_get_the_new_section(self):
        gradle=(APP/"build.gradle.kts").read_text()
        self.assertIn('"        com.ghostdeveloper.spdecode.cloud.NpvsIdentitySettings()\\n" +',gradle)
        settings=(SOURCE.parent/"FunctionalSettingsPanel.kt").read_text()
        self.assertNotIn("NpvsIdentitySettings",settings)
        self.assertIn('dependsOn(prepareQaSettingsSource)',gradle)

    def test_identity_store_and_picker_never_use_history_or_secret_intents(self):
        vault=(SOURCE/"NpvsIdentityVault.kt").read_text()
        for marker in ("noBackupFilesDir","AES/GCM/NoPadding","AndroidKeyStore","AtomicFile",
                       'fingerprint in fingerprints','fileSha256',"PKCS8EncodedKeySpec","sign.verify(signature)"):
            self.assertIn(marker,vault)
        picker=(SOURCE/"NpvsRecipientPicker.kt").read_text()
        self.assertIn("vault.matching(bytes)",picker)
        self.assertIn("SecureFlagPolicy.SecureOn",picker)
        self.assertIn("RadioButton(",picker)
        self.assertIn("mutableStateOf<Pending?>(null)",picker)
        self.assertNotIn("startActivity(",picker)
        self.assertNotIn("Intent(",picker)
        for forbidden in ("HistoryRepository","Telemetry","Log.","println(","privateKey\",",'putExtra("identity"'):
            self.assertNotIn(forbidden,vault+picker)
        manifest=(APP/"src/main/AndroidManifest.xml").read_text()
        self.assertNotIn("NpvsRecipientActivity",manifest)
        gradle=(APP/"build.gradle.kts").read_text()
        self.assertIn("NpvsRecipientPicker.Content()",gradle)
        self.assertIn("NpvsRecipientPicker.isShowing",gradle)

    def test_copy_requires_explicit_action_and_generation_uses_api(self):
        ui=(SOURCE/"NpvsIdentitySettings.kt").read_text()
        for marker in ("client.generateNpvsIdentity()","SecureFlagPolicy.SecureOn",
                       "IS_SENSITIVE","npv_copy_private","npv_import","vault.enable(value)"):
            self.assertIn(marker,ui)
        client=(SOURCE/"CloudDecodeClient.kt").read_text()
        self.assertIn('NpvsRecipientPicker.choose(app,bytes)',client)
        self.assertIn('put("recipientKey",recipient)',client)
        self.assertIn('protectedPost(CloudOperation.IDENTITY',client)
        # Standard Play Integrity covers the same prepared HPKE wire that is sent.
        # Do not regress to a second encryption after requestHash was attested.
        self.assertIn('val prepared=CloudNativeTransport.prepare(operation,exact,attachment)', client)
        self.assertIn('CloudNativeTransport.requestHashHex(prepared.wire)', client)
        self.assertIn('return CloudNativeTransport.post(operation, exact, bearer, id, integrity, prepared=prepared)', client)
        self.assertIn('finally { prepared.discard() }', client)
        self.assertNotIn('return CloudNativeTransport.post(operation, exact, bearer, id, integrity)', client)
        transport=(SOURCE/"CloudNativeTransport.kt").read_text()
        self.assertIn('operation: Int',transport)
        native=(APP/"src/main/cpp/spdecode_transport.cpp").read_text()
        self.assertIn('safeOperation',native)
        self.assertIn('if(isRecipientNpvs && (password!=null || hwid!=null))',client)
        self.assertIn('if(credentials.length()>0)body.put("credentials",credentials)',client)
        self.assertNotIn('if(recipient!=null)body.put("credentials",JSONObject()',client)
        spanish=(APP/"src/main/res/values-es/npvs_identity.xml").read_text()
        self.assertIn("Comparte solo la clave pública",spanish)
        self.assertNotIn("Esto no copia el Keystore oficial",spanish)
        self.assertNotIn('lastDiagnostic=Diagnostic("identity"',client)
        self.assertIn('deleteTarget=entry',ui)
        self.assertIn('if(!hasGeneratedIdentity)',ui)
        self.assertIn('R.string.npv_delete_warning',ui)
        store=(SOURCE/"NpvsIdentityVault.kt").read_text()
        self.assertIn('if(value.optString("source")=="generated"',store)
        for lang in ("values","values-es","values-ar","values-de","values-fa",
                     "values-fr","values-hi","values-in","values-it",
                     "values-ja","values-pt-rBR","values-ru","values-tr","values-vi"):
            xml=(APP/"src/main/res"/lang/"npvs_identity.xml").read_text()
            for key in ("npv_delete_title","npv_delete_warning","npv_cancel",
                        "npv_already_generated","npv_choose_title","npv_generate"):
                self.assertIn('name="'+key+'"',xml)
            self.assertNotIn('Generar con la API',xml)
            self.assertNotIn('Generate with API',xml)


if __name__=="__main__":unittest.main()

