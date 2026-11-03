"""Owner-approved APK/Credits and feedback AMOLED UX; no payments or local decoders."""
from __future__ import annotations

import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/ghostdeveloper/spdecode"
RES = ROOT / "android/app/src/main/res"
LOCALES = (
    "values", "values-es", "values-ar", "values-de", "values-fa", "values-fr",
    "values-hi", "values-in", "values-it", "values-ja", "values-pt-rBR",
    "values-ru", "values-tr", "values-vi",
)
REQUIRED = {
    "apk_import_button", "apk_future_message", "apk_credits_title",
    "apk_credits_intro", "apk_credits_notice", "apk_credits_buy_title",
    "apk_credits_one", "apk_credits_buy_one", "apk_credits_packages",
    "apk_credits_buy_package", "apk_credits_prices_title",
    "apk_credits_subscriptions", "apk_credits_button", "apk_credits_back",
    "feedback_details_title", "feedback_method_description",
    "feedback_bug_description", "feedback_suggestion_description",
    "feedback_extra_title", "feedback_extra_hint",
}


class AndroidUxApprovedPreviewTests(unittest.TestCase):
    def test_all_fourteen_locales_have_complete_new_copy(self):
        self.assertEqual(len(LOCALES), 14)
        for folder in LOCALES:
            with self.subTest(locale=folder):
                path = RES / folder / "ux_preview_strings.xml"
                self.assertTrue(path.is_file(), str(path))
                found = {}
                for string in ET.parse(path).getroot().findall("string"):
                    name = string.attrib["name"]
                    self.assertNotIn(name, found)
                    found[name] = string.text or ""
                self.assertEqual(set(found), REQUIRED)
                self.assertTrue(all(value.strip() for value in found.values()))

    def test_feedback_requires_explicit_category_before_details(self):
        source = (JAVA / "FeedbackScreen.kt").read_text(encoding="utf-8")
        self.assertIn('mutableStateOf<String?>(null)', source)
        self.assertIn('if(category!=null) {', source)
        self.assertIn('testTag("feedback_details")', source)
        self.assertIn('testTag("feedback_category_"+value)', source)
        self.assertIn('testTag("feedback_extra")', source)
        self.assertIn('enabled=valid&&!sending&&receipt==null', source)
        self.assertIn('FeedbackDraft(category!!', source)
        self.assertIn('submissionId', source)
        self.assertIn('onSend(draft)', source)
        self.assertIn('selected.isNotEmpty()', source)
        self.assertIn('combinedText.length<=2000', source)

    def test_apk_has_one_disabled_button_and_no_old_screen_sections(self):
        source = (JAVA / "ApkAnalysisComingSoonScreen.kt").read_text(encoding="utf-8")
        self.assertIn('testTag("apk_analysis_placeholder")', source)
        self.assertIn('testTag("apk_analysis_import_disabled")', source)
        self.assertIn('testTag("apk_credits_screen")', source)
        self.assertIn('testTag("apk_buy_one_disabled")', source)
        self.assertIn('testTag("apk_buy_bundle_disabled")', source)
        self.assertIn('enabled=false', source)
        self.assertNotIn('R.string.apk_analysis_intro_title', source)
        self.assertNotIn('R.string.apk_analysis_steps_title', source)
        self.assertNotIn('R.string.apk_analysis_credit_cost', source)
        self.assertNotIn('R.string.apk_analysis_credit_price', source)

    def test_credits_replace_settings_button_only_for_apk_tab(self):
        source = (JAVA / "SpDecodeApp.kt").read_text(encoding="utf-8")
        self.assertIn('showCreditsAction=activeTab==2 && !creditsPage', source)
        self.assertIn('showCreditsBack=activeTab==2 && creditsPage', source)
        self.assertIn('modifier=Modifier.testTag("apk_credits_open")', source)
        self.assertIn('modifier=Modifier.testTag("apk_credits_back")', source)
        self.assertIn('BackHandler(enabled=creditsPage && activeTab==2)', source)
        self.assertIn('2->if(creditsPage) ApkCreditsComingSoonScreen()', source)
        self.assertIn('onTab={destination->creditsPage=false;onTab(destination)}', source)


if __name__ == "__main__":
    unittest.main()
