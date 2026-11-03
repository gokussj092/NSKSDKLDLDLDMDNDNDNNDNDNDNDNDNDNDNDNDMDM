"""Static regression contracts for the global Cloud UI and all localized copy."""
from pathlib import Path
import hashlib
import json
import re
import unittest
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
ANDROID=ROOT/"android/app"
LOCALES=("values","values-es","values-pt-rBR","values-ar","values-fa",
         "values-fr","values-in","values-ru","values-de","values-tr",
         "values-vi","values-hi","values-ja","values-it")
CLOUD_KEYS={"cloud_global_title","cloud_global_auto","cloud_global_hint",
            "cloud_global_action","cloud_global_detail","cloud_global_invalid"}

def text(path):
    return (ROOT/path).read_text(encoding="utf-8")

def resources(directory,filename):
    root=ET.parse(ANDROID/"src/main/res"/directory/filename).getroot()
    return {item.attrib["name"]:item.text for item in root.findall("string")}

class GlobalCloudUiContracts(unittest.TestCase):
    def test_all_14_locales_have_nonempty_global_cloud_copy(self):
        for locale in LOCALES:
            with self.subTest(locale=locale):
                found=resources(locale,"global_cloud_strings.xml")
                self.assertEqual(set(found),CLOUD_KEYS)
                self.assertTrue(all(val and val.strip() for val in found.values()))
                self.assertTrue(all("%1$s" not in val for val in found.values()))

    def test_compatible_export_is_short_targeted_and_translated(self):
        for locale in LOCALES:
            with self.subTest(locale=locale):
                found=resources(locale,"compatible_export_strings.xml")
                self.assertEqual(found["compatible_export_redecode"].count("%1$s"),1)
                self.assertLess(len(found["compatible_export_redecode"]),180)
                self.assertEqual(found["compatible_export_for"].count("%1$s"),1)
                self.assertLess(len(found["compatible_export_for"]),180)
        button=text("android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CompatibleExportButton.kt")
        # The translated action uses verified target metadata from the server;
        # a legacy fixed list would suppress legitimate new Unlocked exports.
        self.assertIn("Text(stringResource(R.string.compatible_export_for,artifact.targetAppName))",button)
        self.assertIn("if(artifact!=null)",button)
        self.assertNotIn("CompatibleExportArtifact.targets.getValue",button)

    def test_private_screen_contrast_has_exact_am_ol_ed_colors(self):
        source=text("android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/PrivateScreenSettings.kt")
        self.assertIn("color=Color.White",source)
        self.assertIn("color=Color(0xFFABABAB)",source)
        for locale in LOCALES:
            source_file="strings.xml" if locale in ("values","values-es") else "private_screen.xml"
            strings=resources(locale,source_file)
            self.assertTrue(strings["private_screen_title"])
            self.assertTrue(strings["private_screen_detail"])

    def test_cloud_provider_picker_is_vertical_accessible_and_keeps_routes(self):
        ui=text("android/app/src/main/java/com/ghostdeveloper/spdecode/GlobalCloudImportPanel.kt")
        self.assertNotIn("horizontalScroll",ui)
        self.assertNotIn("FilterChip(",ui)
        self.assertIn("Role.RadioButton",ui)
        self.assertIn(".selectable(",ui)
        self.assertIn('selected=="auto"',ui)
        self.assertIn('onSelect={selected="auto"}',ui)
        self.assertIn("providers.forEach",ui)
        self.assertIn("CloudOnlineReference.options(routes)",ui)
        self.assertIn("onDecode(selected,reference)",ui)

    def test_private_screen_uses_full_settings_card_and_secure_flag(self):
        ui=text("android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/PrivateScreenSettings.kt")
        self.assertIn("RoundedCornerShape(16.dp)",ui)
        self.assertIn("Color(0xFF242424)",ui)
        self.assertIn("Icons.Outlined.Lock",ui)
        self.assertIn("FLAG_SECURE",ui)
        self.assertIn('putBoolean("private-screen",value)',ui)

    def test_notification_sound_and_channel_contract(self):
        import wave
        ui=text("android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudNotifications.kt")
        self.assertIn('CHANNEL="service-notices-chime-v2"',ui)
        self.assertIn('LEGACY_CHANNEL="service-notices-v1"',ui)
        self.assertIn("setUsage(AudioAttributes.USAGE_NOTIFICATION)",ui)
        self.assertIn('"/raw/spdecode_notification"',ui)
        self.assertIn("manager.createNotificationChannel(channel)",ui)
        self.assertIn("previous.sound==null",ui)
        sound=ANDROID/"src/main/res/raw/spdecode_notification.wav"
        with wave.open(str(sound)) as audio:
            self.assertEqual(audio.getnchannels(),1)
            self.assertEqual(audio.getsampwidth(),2)
            self.assertGreater(audio.getnframes(),audio.getframerate()//2)
            self.assertLess(audio.getnframes(),audio.getframerate()*2)

    def test_frozen_c0_ui_remains_bit_for_bit_unchanged(self):
        baseline=json.loads(text("docs/cloud/C0_UI_BASELINE.json"))
        approved=json.loads(text("docs/cloud/C0_UI_APPROVED_1_1_26.json"))["uiGitBlobSha1"]
        for filename in ("SpDecodeApp.kt","HttpInjectorCloudPanel.kt"):
            path="android/app/src/main/java/com/ghostdeveloper/spdecode/"+filename
            content=(ROOT/path).read_bytes()
            actual=hashlib.sha1(b"blob "+str(len(content)).encode()+bytes([0])+content).hexdigest()
            self.assertEqual(actual,approved.get(path,baseline["uiGitBlobSha1"][path]))

    def test_cloud_source_injection_and_existing_routes_are_kept(self):
        script=text("android/app/build.gradle.kts")
        self.assertIn("prepareCloudOnlySources",script)
        activity=text("android/app/src/main/java/com/ghostdeveloper/spdecode/MainActivity.kt")
        app=text("android/app/src/main/java/com/ghostdeveloper/spdecode/SpDecodeApp.kt")
        self.assertIn('onDecodeCloud={reference->decodeCloud("auto",reference)}',activity)
        self.assertIn("CloudOnlineReference.resolve(",activity)
        self.assertIn("HttpInjectorCloudPanel(",app)
        self.assertIn("onDecodeCloud:(String)->Unit",app)
        cloud=text("android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudOnlineReference.kt")
        self.assertIn('Provider("ehi","HTTP Injector Cloud")',cloud)
        self.assertIn('Provider("hc","HTTP Custom Cloud")',cloud)
        gateway=text("cloud/web/lib/c35-gateway.mjs")
        self.assertIn('kind=hasProvider?body.provider:"ehi"',gateway)
        self.assertIn('["ehi","hc"].includes(kind)',gateway)
        self.assertIn('delete body.provider',gateway)
        self.assertIn("requireSession(redis,request,settings())",gateway)

if __name__=="__main__":
    unittest.main()
