"""Cloud client classification and backend-only Server VPN handoff contracts."""
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
JAVA=ROOT/"android/app/src/main/java/com/ghostdeveloper/spdecode"
GRADLE=ROOT/"android/app/build.gradle.kts"
LOCALES=("values","values-es","values-fr","values-de","values-in",
         "values-pt-rBR","values-ru","values-fa","values-ar")

class CloudUserErrorsContracts(unittest.TestCase):
    def test_qa_never_silently_falls_back_to_integrity(self):
        source=(JAVA/"cloud/CloudDecodeClient.kt").read_text("utf-8")
        self.assertIn('if(BuildConfig.SPDECODE_QA_BUILD && code.isEmpty())',source)
        self.assertIn('throw IOException("CLOUD_QA_CODE_REQUIRED")',source)
        self.assertIn('cloudClient.inspectHcRequirements(preview)',(JAVA/"MainActivity.kt").read_text("utf-8"))
        self.assertIn('"HWID_PASSWORD_REQUIRED"->true to true',source)

    def test_bounded_status_and_no_transport_details_in_dialogs(self):
        source=(JAVA/"cloud/CloudUserErrors.kt").read_text("utf-8")
        for code in ("UNAUTHORIZED","INTEGRITY_REJECTED","QA_ACCESS_DENIED","ENGINE_TIMEOUT",
                     "RATE_LIMITED","PASSWORD_REQUIRED","HWID_REQUIRED","HWID_PASSWORD_REQUIRED",
                     "AUTH_FAILED","UNSUPPORTED_FORMAT","SERVICE_MAINTENANCE","CLOUD_QA_CODE_REQUIRED",
                     "CLOUD_NATIVE_NETWORK_UNAVAILABLE"):
            self.assertIn(code,source)
        for status in (401,403,404,408,409,413,422,429,500,502,503,504):
            self.assertRegex(source,r"\b"+str(status)+r"\b")
        self.assertIn('R.string.cloud_failure_offline',source)
        self.assertNotIn('cause.toString()',source)
        self.assertNotIn('cause.stackTrace',source)

    def test_all_supported_locales_define_exact_same_error_keys(self):
        reference=None
        for locale in LOCALES:
            location=ROOT/"android/app/src/main/res"/locale/"cloud_error_strings.xml"
            root=ET.parse(location).getroot()
            strings={child.attrib["name"]:child.text or "" for child in root}
            self.assertTrue(all(strings.values()),locale)
            self.assertTrue(all(k.startswith("cloud_failure_") for k in strings),locale)
            if reference is None:reference=set(strings)
            self.assertEqual(reference,set(strings),locale)
        self.assertEqual(len(reference),27)
        self.assertIn('cloud_failure_maintenance',reference)

    def test_cloud_messages_are_used_without_touching_legacy_app_ui(self):
        source=(JAVA/"MainActivity.kt").read_text("utf-8")
        self.assertGreaterEqual(source.count("CloudUserErrors.message"),4)
        generated=GRADLE.read_text("utf-8")
        self.assertIn("cloudFailureMessages",generated)
        self.assertIn("cloud_failure_notice_title",generated)
        self.assertIn("CloudUserErrors.message",generated)
        manifest=(ROOT/"android/app/src/main/AndroidManifest.xml").read_text("utf-8")
        self.assertEqual(manifest.count("<uses-permission"),1)

    def test_server_vpn_handoff_has_no_client_decoder_work(self):
        guide=(ROOT/"docs/cloud/SERVER_VPN_NEXT_CHAT_GUIDE.md").read_text("utf-8")
        self.assertIn("decoders/Python/apps/",guide)
        self.assertIn("catalog_vpn_bridge.py",guide)
        self.assertIn("backend Cloud",guide)
        self.assertIn("No modifiques el diseño Android",guide)
        self.assertIn("No incluir en el APK métodos de descifrado",guide)
        self.assertIn("ajustar exclusivamente carga",guide)

if __name__=="__main__":
    unittest.main()
