"""Source-bound F7 QA Android guardrails. Kotlin/JNI compilation remains a separate CI gate."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
JAVA=ROOT/"android/app/src/main/java/com/ghostdeveloper/spdecode"

def content(path:str)->str:
    return (JAVA/path).read_text("utf-8")

class APKQAAndroidResumeContracts(unittest.TestCase):
    def test_keystore_encrypted_checkpoint_no_backup(self):
        source=content("cloud/CloudApkQaCheckpoint.kt")
        for required in ("AndroidKeyStore","AES/GCM/NoPadding","noBackupFilesDir",
                         "AtomicFile","setRandomizedEncryptionRequired(true)"):
            self.assertIn(required,source)
        self.assertNotIn("getSharedPreferences(",source)

    def test_unique_network_constrained_worker(self):
        source=content("cloud/ApkQaWorker.kt")
        for required in ("CoroutineWorker","NetworkType.CONNECTED",
                         "ExistingWorkPolicy.KEEP","ExistingWorkPolicy.REPLACE",
                         "executeQueued()","CancellationException"):
            self.assertIn(required,source)
        self.assertNotIn("Log.",source)

    def test_server_confirmed_resume_and_one_apk_at_time(self):
        client=content("cloud/CloudApkQaClient.kt")
        ui=content("ApkQaAnalysisScreen.kt")
        host=content("MainActivity.kt")
        for required in ("clientStartId","nextChunk","receivedBytes",
                         "APK_QA_FILE_CHANGED","takePersistableUriPermission",
                         "checkpoint.save","MAX_BYTES=100L*1000L*1000L"):
            self.assertIn(required,client)
        self.assertIn("enabled=authorized&&!active",ui)
        self.assertIn("apk_qa_one_at_time",ui)
        self.assertNotIn("apk_qa_copy_device_id",ui)
        self.assertNotIn("onApkQaCopyDeviceId",host)
        self.assertIn("apkQaClient.queue(uri)",host)
        self.assertNotIn("apkQaJob?.cancel()",host)

    def test_no_qa_auth_bypass_or_new_public_endpoints(self):
        client=content("cloud/CloudApkQaClient.kt")
        server=(ROOT/"cloud/apk_analysis/qa_service.py").read_text("utf-8")
        self.assertIn("cloud.apkQaRequest(",client)
        self.assertNotIn("https://",client)
        self.assertIn("MAX_ACTIVE = 1",server)
        self.assertIn("_recover_jobs()",server)
        self.assertIn('hmac.compare_digest(digest(secret)',server)

if __name__=="__main__":
    unittest.main()
