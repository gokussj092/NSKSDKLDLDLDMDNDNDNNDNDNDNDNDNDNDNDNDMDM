"""Cloud-only history JSON export + large result safety contract.

Do not edit C0-frozen UI sources: Gradle creates copies for Cloud builds.
"""
import unittest
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/"android/app"
GRADLE=(APP/"build.gradle.kts").read_text(encoding="utf-8")
ACTION=(APP/"src/main/java/com/ghostdeveloper/spdecode/cloud/CloudHistoryActions.kt").read_text(encoding="utf-8")
SOURCE=(APP/"src/main/java/com/ghostdeveloper/spdecode/SpDecodeApp.kt").read_text(encoding="utf-8")
ACTIVITY=(APP/"src/main/java/com/ghostdeveloper/spdecode/MainActivity.kt").read_text(encoding="utf-8")

class CloudHistoryActionsTest(unittest.TestCase):
    def test_frozen_ui_unmodified_and_overlay_generated(self):
        self.assertNotIn("CloudHistoryEntryActions(",SOURCE)
        self.assertNotIn("CloudLargeResultNotice(",SOURCE)
        self.assertNotIn("presentDecodedRecord(",ACTIVITY)
        self.assertIn('val prepareCloudHistoryUiSource = tasks.register(',GRADLE)
        self.assertIn('exclude("com/ghostdeveloper/spdecode/SpDecodeApp.kt")',GRADLE)
        self.assertIn('exclude("com/ghostdeveloper/spdecode/MainActivity.kt")',GRADLE)
        self.assertIn('from(cloudHistoryUiRoot)',GRADLE)
        self.assertIn('dependsOn(prepareCloudHistoryUiSource)',GRADLE)

    def test_export_is_user_selected_json_and_never_eager_parses_nur(self):
        self.assertIn('ActivityResultContracts.CreateDocument("application/json")',ACTIVITY)
        self.assertIn('jsonExporter.launch("$safe-decoded.json")',ACTIVITY)
        self.assertIn('contentResolver.openOutputStream(uri,"w")',ACTIVITY)
        self.assertIn('if (entry.extension == "nurservers") entry.rawText',ACTION)
        self.assertIn('ResultPresentation.formatted(entry.document, ResultExport.JSON)',ACTION)
        self.assertIn('CloudHistoryJsonExport.content(entry)',GRADLE)
        self.assertIn('onExportHistory(entry)',GRADLE)
        self.assertIn('onDelete={deletingAll=false;deletion=setOf(entry.id)}',GRADLE)

    def test_warning_and_progress_are_cloud_only(self):
        self.assertIn('BuildConfig.SPDECODE_CLOUD_ENABLED && progressStage==1',GRADLE)
        self.assertIn('cloud_decode_progress_message',GRADLE)
        self.assertIn('BuildConfig.SPDECODE_CLOUD_ENABLED && stored',GRADLE)
        self.assertIn('entry.extension=="nurservers" || entry.rawText.length>=250_000',GRADLE)
        self.assertIn('presentDecodedRecord(record,saved)',GRADLE)
        self.assertIn('onDismissLargeResultWarning',GRADLE)
        self.assertIn('CloudLargeResultNotice',ACTION)
        self.assertIn('CloudHistoryEntryActions',ACTION)

    def test_all_supported_languages_have_every_message(self):
        names={"cloud_decode_progress_title","cloud_decode_progress_message",
               "cloud_large_result_title","cloud_large_result_body",
               "cloud_large_result_acknowledge","cloud_history_actions"}
        dirs=("values","values-es","values-pt-rBR","values-ar","values-fa",
              "values-fr","values-in","values-ru","values-de")
        for name in dirs:
            with self.subTest(locale=name):
                path=APP/"src/main/res"/name/"cloud_history_strings.xml"
                items=ET.parse(path).getroot().findall("string")
                self.assertEqual({i.attrib["name"] for i in items},names)
                self.assertTrue(all((i.text or "").strip() for i in items))

if __name__=="__main__":
    unittest.main()
