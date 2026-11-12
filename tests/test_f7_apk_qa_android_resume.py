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

    def test_history_is_encrypted_durable_and_preserves_old_report(self):
        store=content("cloud/ApkQaHistoryStore.kt")
        client=content("cloud/CloudApkQaClient.kt")
        for required in ("AndroidKeyStore","AES/GCM/NoPadding","AtomicFile",
                         "noBackupFilesDir","fun save(","fun read(","fun list(",
                         "fun delete(","finishWrite(","KEY_ALIAS"):
            self.assertIn(required,store)
        self.assertNotIn("SharedPreferences",store)
        self.assertNotIn("uploadToken",store)
        self.assertIn("history.save(terminal,report.toString())",client)
        self.assertLess(client.index("history.save(terminal,report.toString())"),
                        client.index("checkpoint.save(terminal)"))
        self.assertIn("historyItems()",client)
        self.assertIn("historyRecord(id:String)",client)
        self.assertIn("history.save(previous,previous.report)",client)

    def test_apk_export_and_history_use_full_original_report(self):
        ui=content("ApkQaAnalysisScreen.kt")
        host=content("MainActivity.kt")
        markdown=content("ApkReportMarkdown.kt")
        for required in ("ActivityResultContracts.CreateDocument",
                         "openOutputStream(uri","OutputStreamWriter(output",
                         "apk_qa_export_json","ApkQaHistoryStore",
                         "historyStore.read(item.id)","historyStore.delete(item.id)",
                         "LargeResultViewer(","publicStages("):
            self.assertIn(required,ui)
        self.assertIn('ApkReportBlock("JSON","json",report)',markdown)
        self.assertNotIn("pretty.toJson(root)",markdown)
        self.assertIn("apkQaReport=latest.report",host)
        self.assertNotIn("org.json.JSONObject(raw).toString(2)",host)

    def test_select_continuous_json_range_without_fragment_dialog(self):
        viewer=content("ContinuousJsonView.kt")
        large=content("LargeResultViewer.kt")
        native=content("results/NativeResultEngine.kt")
        self.assertIn("ActionMode.TYPE_FLOATING",viewer)
        self.assertIn("movingHandle",viewer)
        self.assertIn("postOnAnimation(autoScroll)",viewer)
        self.assertIn("orderedSelection()",viewer)
        self.assertIn("onCopyRange(",viewer)
        self.assertIn("current.selectedText(",large)
        self.assertNotIn("if (snippet != null)",large)
        self.assertIn("fun selectedText(",native)

    def test_stage_activity_never_marks_started_stage_done(self):
        ui=content("ApkQaAnalysisScreen.kt")
        service=(ROOT/"cloud/apk_analysis/qa_service.py").read_text("utf-8")
        self.assertIn('else->"RUNNING" // Never display a green tick',ui)
        self.assertIn('stage.status',ui)
        self.assertIn('CircularProgressIndicator(',ui)
        self.assertIn("ADVANCED_ANALYSIS_PARTIAL",service)
        self.assertIn('"PARTIAL"',service)

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
