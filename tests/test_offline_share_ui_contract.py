#!/usr/bin/env python3
"""Static regression contract for isolated Android offline share/import/error UI."""
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

APP=Path("android/app/src/offlineNative")
ROOT=Path("android/app/src/main/cpp")
ANDROID="{http://schemas.android.com/apk/res/android}"

class OfflineImportContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest=ET.parse(APP/"AndroidManifest.xml").getroot()
        cls.ui=(APP/"java/com/ghostdeveloper/spdecode/offline/OfflineUi.kt").read_text()
        cls.activity=(APP/"java/com/ghostdeveloper/spdecode/offline/MainActivity.kt").read_text()
        cls.strings=(APP/"java/com/ghostdeveloper/spdecode/offline/OfflineText.kt").read_text()
        cls.errors=(APP/"java/com/ghostdeveloper/spdecode/offline/OfflineErrorMessages.kt").read_text()
        cls.bridge=(ROOT/"spdecode_offline_native.cpp").read_text()
        cls.splash=(APP/"java/com/ghostdeveloper/spdecode/offline/OfflineSplashScreen.kt").read_text()
        cls.json_viewer=(APP/"java/com/ghostdeveloper/spdecode/offline/OfflineJson.kt").read_text()

    def test_share_and_view_exported_activity(self):
        activity=self.manifest.find(".//activity")
        self.assertEqual(activity.get(ANDROID+"exported"),"true")
        actions={n.get(ANDROID+"name") for n in activity.findall(".//action")}
        for action in ("android.intent.action.MAIN","android.intent.action.VIEW",
                       "android.intent.action.SEND"):
            self.assertIn(action,actions)
        self.assertNotIn("android.permission.INTERNET",ET.tostring(self.manifest).decode())

    def test_handles_external_uris_and_protects_unsupported(self):
        for required in ("onNewIntent(intent:Intent)","handleExternalIntent(intent)",
                         "importIncomingFile(uri)","supportedFiles",
                         "Intent.EXTRA_STREAM","Intent.ACTION_SEND",
                         "Intent.ACTION_VIEW","uri.scheme!=\"content\"",
                         "readableDecodeError(\"UNSUPPORTED_FORMAT\""):
            self.assertIn(required,self.activity)
        self.assertIn('"hat"',self.activity)
        self.assertIn('"darktunnel"',self.activity)

    def test_crypto_only_in_cpp_and_wiring(self):
        self.assertIn('#include "spdecode_hat_tunnel.h"',self.bridge)
        self.assertIn("decodeHatTunnel(source)",self.bridge)
        self.assertIn('format=="hat"',self.bridge)
        self.assertIn('format=="darktunnel"',self.bridge)
        self.assertIn('first in setOf("dt","dtunnel","dark","darktunnel"',self.activity)
        self.assertNotIn("Cipher.getInstance",self.activity)

    def test_errors_have_clear_alert_and_no_codes_to_user(self):
        self.assertIn("state.error?.let { problem ->",self.ui)
        self.assertIn("AlertDialog(onDismissRequest={state.error=null}",self.ui)
        self.assertIn("ui.error=readableDecodeError(reason,suffix,ui.language)",self.activity)
        for code in ("HC_UNSUPPORTED_SCHEMA","HAT_UNSUPPORTED_VERSION",
                     "NPV_RECIPIENT_MISMATCH","NPV_RECIPIENT_V1_UNSUPPORTED",
                     "UNSUPPORTED_OFFLINE_FORMAT","FILE_TOO_LARGE"):
            self.assertIn(code,self.errors)
        self.assertNotIn('\" ($code)\"',self.activity)

    def test_screen_recording_is_never_blocked(self):
        # A screen recorder must see the Offline UI, including result screens.
        for source in (APP/"java").rglob("*.kt"):
            self.assertNotIn("FLAG_SECURE",source.read_text(),str(source))
            self.assertNotIn("setFlags(",source.read_text(),str(source))
        self.assertNotIn("FLAG_SECURE",ET.tostring(self.manifest).decode())
        self.assertNotIn("private-screen",self.ui)

    def test_offline_splash_matches_online_startup(self):
        self.assertIn("if(showBrandedSplash.value) OfflineSplashScreen(ui.language)",self.activity)
        self.assertIn("splashStarted=SystemClock.elapsedRealtime()",self.activity)
        self.assertIn("postDelayed({showBrandedSplash.value=false}",self.activity)
        self.assertIn("5_000L",self.activity)
        self.assertIn("1_600L",self.activity)
        self.assertIn("offline_launcher_foreground",self.splash)
        self.assertIn("CircularProgressIndicator",self.splash)
        self.assertIn('txt("splash_subtitle",language)',self.splash)
        self.assertIn('txt("splash_powered_by",language)',self.splash)
        for lang in ("en","es","pt-BR","ar","fa","fr","id","ru","de",
                     "tr","vi","hi","ja","it"):
            self.assertIn(f'"{lang}" to mapOf(',self.strings)
        self.assertIn("Configuration decoder",self.strings)
        self.assertIn("Powered by Ghost Developer",self.strings)

    def test_nested_json_presentation_preserves_original_history(self):
        # The viewer and the two full-result actions share the same formatter.
        self.assertIn("fun formatExpanded(source:String):String",self.json_viewer)
        self.assertIn("is JSONObject,is JSONArray -> expandEmbedded(nested,depth+1)",self.json_viewer)
        self.assertIn("nestedReader.nextClean()=='\\u0000'",self.json_viewer)
        self.assertIn("if(depth>=32)return value",self.json_viewer)
        self.assertIn("if(!looksLikeJson)value",self.json_viewer)
        self.assertIn("OfflineJson.formatExpanded(state.result.orEmpty())",self.ui)
        self.assertIn("copy(OfflineJson.formatExpanded(it))",self.activity)
        self.assertIn("exportPayload=OfflineJson.formatExpanded(it)",self.activity)
        # Original native JSON values continue to be stored in encrypted history.
        self.assertIn("OfflineJson.format(source)",self.activity)
        self.assertIn("storage.save(record)",self.activity)
        self.assertIn("OfflineJson.format(item.json)",self.activity)

    def test_no_implementation_jargon_in_visible_strings(self):
        values=re.findall(r'"[^"]+" to "((?:[^"\\]|\\.)*)"',self.strings)
        self.assertGreater(len(values),280)
        self.assertFalse([v for v in values if "C++" in v or "JNI" in v or
            re.search(r"\bnativ[oaes]\b",v,flags=re.IGNORECASE)])
        self.assertIn("Offline edition",self.strings)

if __name__=="__main__":
    unittest.main()
