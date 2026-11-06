"""R0 regression gates for release R8/native bridge and NPVS Cloud-only flow.

Static checks intentionally do not decrypt a file, load keystore secrets, or
make network calls. Real R8 APK/AAB and physical-device checks are separate.
"""
import re
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/"android/app"
CPP=APP/"src/main/cpp"
CLOUD=APP/"src/main/java/com/ghostdeveloper/spdecode/cloud"


def read(path):
    return path.read_text(encoding="utf-8")


class R0R8NpvsContracts(unittest.TestCase):
    def test_release_uses_r8_and_cloud_only_sources(self):
        gradle=read(APP/"build.gradle.kts")
        self.assertIn("isMinifyEnabled = true",gradle)
        self.assertIn("isShrinkResources = true",gradle)
        self.assertIn('proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt")',gradle)
        self.assertIn('require(enableCloud) { "Release distribution requires the Cloud-only source set" }',gradle)
        self.assertIn('exclude("com/ghostdeveloper/spdecode/parity/**")',gradle)
        self.assertIn('java.setSrcDirs(listOf(cloudSourceRoot))',gradle)

    def test_hpke_context_outlives_play_and_heavy_catalog_budget(self):
        import re
        hpke=read(CPP/"spdecode_hpke.cpp")
        transport=read(CPP/"spdecode_transport.cpp")
        ttl=int(re.search(r"Clock::now\(\)-std::chrono::seconds\((\d+)\)",hpke).group(1))
        read_ms=int(re.search(r"kNurCatalogReadTimeoutMs = (\d+)",transport).group(1))
        self.assertGreater(ttl*1000,60_000+30_000+10_000+read_ms)

    def test_r8_keeps_exact_registered_jni_and_keystore_bridge(self):
        from scripts.ci.current_android_contracts import jni_registry
        rules=read(APP/"proguard-rules.pro")
        native=read(CPP/"spdecode_transport.cpp")
        kotlin=read(CLOUD/"CloudNativeTransport.kt")
        cmake=read(CPP/"CMakeLists.txt")
        exports=read(CPP/"spdecode.exports")
        self.assertIn("-keepclasseswithmembers,includedescriptorclasses class com.ghostdeveloper.spdecode.cloud.CloudNativeTransport",rules)
        self.assertIn("-keep class com.ghostdeveloper.spdecode.cloud.CloudKeystorePlatform",rules)
        self.assertNotIn("-keep class com.ghostdeveloper.spdecode.**",rules)
        self.assertIn('System.loadLibrary("v7q3")',kotlin)
        methods=jni_registry(native,kotlin)
        self.assertGreater(len(methods),0)
        self.assertIn("nativeRuntimeReport",methods)
        self.assertIn('add_library(v7q3 SHARED',cmake)
        self.assertIn("JNI_OnLoad;",exports)
        self.assertIn("local: *;",exports)
        for flag in ("-fstack-protector-strong","-D_FORTIFY_SOURCE=2",
                     "-Wl,-z,relro,-z,now","-Wl,-z,noexecstack"):
            self.assertIn(flag,cmake)

    def test_cloud_hpke_reuses_standard_play_integrity_authenticated_wire(self):
        client=read(CLOUD/"CloudDecodeClient.kt")
        native=read(CLOUD/"CloudNativeTransport.kt")
        envelope=read(CLOUD/"V2HpkeEnvelope.kt")
        self.assertIn("val prepared=CloudNativeTransport.prepare(operation,exact,attachment)",client)
        self.assertIn("CloudNativeTransport.requestHashHex(prepared.wire)",client)
        self.assertIn("return CloudNativeTransport.post(operation, exact, bearer, id, integrity, prepared=prepared)",client)
        self.assertIn("finally { prepared.discard() }",client)
        self.assertIn("StandardIntegrityManager.StandardIntegrityTokenRequest.builder().setRequestHash(requestHash)",client)
        self.assertIn("nativePrepareHpke",native)
        self.assertIn("nativeOpenHpke",native)
        self.assertIn("nativeDiscardHpke",native)
        self.assertIn("if(status in 200..299)throw IOException(\"CLOUD_HPKE_REPLY_REQUIRED\")",native)
        self.assertIn("plaintext.fill(0)",envelope)
        self.assertIn("wire.fill(0)",envelope)
        self.assertNotIn("/api/v2/",client)

    def test_npvs_v5_v6_recipient_requires_explicit_opt_in(self):
        client=read(CLOUD/"CloudDecodeClient.kt")
        picker=read(CLOUD/"NpvsRecipientPicker.kt")
        vault=read(CLOUD/"NpvsIdentityVault.kt")
        self.assertIn('val isRecipientNpvs=format=="npvs"',client)
        self.assertIn("NpvsRecipientProbe.fingerprints(bytes).isNotEmpty()",client)
        self.assertIn('if(isRecipientNpvs && (password!=null || hwid!=null))',client)
        self.assertIn('NpvsRecipientPicker.choose(app,bytes)',client)
        self.assertIn('credentials.put("recipientKey",recipient)',client)
        self.assertIn('if(credentials.length()>0)body.put("credentials",credentials)',client)
        self.assertIn("if(!enabled())return emptyList()",vault)
        self.assertIn('data[4].toInt() !in setOf(5,6)',vault)
        self.assertIn('noBackupFilesDir',vault)
        self.assertIn('KeyStore.getInstance("AndroidKeyStore")',vault)
        self.assertIn('"AES/GCM/NoPadding"',vault)
        self.assertIn('vault.matching(bytes)',picker)
        self.assertIn('SecureFlagPolicy.SecureOn',picker)
        self.assertIn('PRIVATE_KEY_REQUIRED',picker)
        self.assertNotIn('Intent(',picker)

    def test_npvs_worker_keeps_v1_v5_v6_and_password_contract(self):
        worker=read(ROOT/"cloud/workers/python/npvs_bridge.py")
        tests=read(ROOT/"tests/test_cloud_npvs_packaging.py")
        workflow=read(ROOT/".github/workflows/cloud-c2.yml")
        self.assertIn("npvs",worker.lower())
        for marker in ("PASSWORD_REQUIRED","AUTH_FAILED","decode_file(\"npvs\", raw, credentials=creds)"):
            self.assertIn(marker,workflow)
        self.assertIn('decode_file("npvs",raw,credentials={"recipientKey":json.dumps(identity)})',
                      read(ROOT/"tests/test_npvs_identity.py"))
        self.assertIn("cloud/workers/python/npvs_bridge.py",tests)


if __name__ == "__main__":
    unittest.main()
