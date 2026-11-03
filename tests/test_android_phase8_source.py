"""Phase 8: source-level release guards, without an additional QA application.

These tests run in the existing Python suite and require no Android SDK.
Native/device assertions are separately enforced by the Android CI job.
"""
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "android" / "app"
RES = APP / "src" / "main" / "res"
LOCALES = (
    "values", "values-ar", "values-de", "values-es",
    "values-fa", "values-fr", "values-hi", "values-in",
    "values-it", "values-ja", "values-pt-rBR",
    "values-ru", "values-tr", "values-vi",
)
REQUIRED_GROUPS = (
    "about_screen_strings.xml",
    "feedback_strings.xml",
    "network_update_strings.xml",
)


def strings_for(folder: str, name: str) -> dict[str, str]:
    file = RES / folder / name
    root = ET.parse(file).getroot()
    if root.tag != "resources":
        raise AssertionError(f"{file}: root must be resources")
    strings: dict[str, str] = {}
    for item in root.findall("string"):
        key = item.attrib["name"]
        if key in strings:
            raise AssertionError(f"{file}: duplicate {key}")
        strings[key] = "".join(item.itertext()).strip()
    return strings


class Phase8SourceGuards(unittest.TestCase):
    def test_candidate_is_real_1_1_26_build_41(self):
        gradle = (APP / "build.gradle.kts").read_text(encoding="utf-8")
        self.assertRegex(gradle, r"(?m)^\s*versionName\s*=\s*\"1\.1\.26\"\s*$")
        self.assertRegex(gradle, r"(?m)^\s*versionCode\s*=\s*41\s*$")
        self.assertIn('applicationId = "com.ghostdeveloper.spdecode"', gradle)
        self.assertIn('require(!enableQaBuild)', gradle)
        self.assertNotIn("productFlavors {", gradle)
        self.assertIn("isMinifyEnabled", gradle)

    def test_all_14_languages_have_phase_resources(self):
        self.assertEqual(len(LOCALES), 14)
        for name in REQUIRED_GROUPS:
            with self.subTest(group=name):
                base = strings_for("values", name)
                self.assertTrue(base, name)
                for locale in LOCALES[1:]:
                    with self.subTest(locale=locale):
                        actual = strings_for(locale, name)
                        self.assertEqual(set(actual), set(base))
                        self.assertTrue(all(actual.values()))

    def test_about_version_comes_from_buildconfig(self):
        about = (APP / "src/main/java/com/ghostdeveloper/spdecode/AboutScreen.kt").read_text(encoding="utf-8")
        self.assertIn("BuildConfig.VERSION_NAME", about)
        self.assertIn("BuildConfig.VERSION_CODE", about)
        self.assertIn("SupportedLanguages.options", about)
        self.assertIn("about_screen", about)

    def test_paid_apk_analysis_stays_inert(self):
        preview = (APP / "src/main/java/com/ghostdeveloper/spdecode/ApkAnalysisComingSoonScreen.kt").read_text(encoding="utf-8")
        self.assertIn("apk_analysis_placeholder", preview)
        self.assertIn("apk_analysis_import_disabled", preview)
        self.assertRegex(preview, r"OutlinedButton\s*\(\s*onClick\s*=\s*\{\s*\},\s*enabled\s*=\s*false")
        for forbidden in ("BillingClient", "ACTION_OPEN_DOCUMENT", "POST /api/", "purchaseToken", "createAnalysisJob"):
            self.assertNotIn(forbidden, preview)

    def test_feedback_and_badges_are_present(self):
        feedback = (APP / "src/main/java/com/ghostdeveloper/spdecode/FeedbackScreen.kt").read_text(encoding="utf-8")
        self.assertIn("feedback_", feedback)
        badges = (APP / "src/main/java/com/ghostdeveloper/spdecode/ServerVpnBadgePriority.kt").read_text(encoding="utf-8")
        self.assertIn("maintenance", badges.lower())


if __name__ == "__main__":
    unittest.main()
