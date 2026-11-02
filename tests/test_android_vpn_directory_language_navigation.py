"""Phase 5 UI contracts: new VPN badges attach to providers, language has a screen."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/"android/app/src/main/java/com/ghostdeveloper/spdecode"

class DirectoryAndLanguageNavigation(unittest.TestCase):
    def test_manual_refresh_remains_available_but_has_no_new_feature_badge(self):
        src=(SRC/"SpDecodeApp.kt").read_text("utf-8")
        start=src.index("private fun ServerVpnScreen(")
        end=src.index("@Composable\nprivate fun ServerVpnNewTag",start)
        code=src[start:end]
        header=src[src.index("private fun BrandHeader("):start]
        self.assertIn('testTag("server_vpn_manual_refresh")',header)
        self.assertIn("onClick=onRefreshServerVpn",header)
        self.assertNotIn('testTag("server_vpn_manual_refresh")',code)
        self.assertNotIn("manualRefreshIsNew",code)
        self.assertNotIn("featureRemaining(",code)
        self.assertIn("newlyAdded=app.id in newProviderIds",code)
        self.assertIn("ServerVpnNewTag()",code)
        self.assertIn("snapshot.nextExpiryMs",code)

    def test_language_page_replaces_bottom_sheet_without_breaking_settings(self):
        src=(SRC/"FunctionalSettingsPanel.kt").read_text("utf-8")
        screen=(SRC/"LanguageSelectionScreen.kt").read_text("utf-8")
        self.assertIn("languagePage by rememberSaveable",src)
        self.assertIn("BackHandler(enabled=languagePage || formatsPage || feedbackPage || aboutPage)",src)
        self.assertIn("LanguageSelectionScreen(",src)
        self.assertNotIn("languageSheet",src)
        self.assertNotIn("ModalBottomSheet",src)
        self.assertIn('testTag("settings_language_screen")',screen)
        self.assertIn('testTag("settings_language_back")',screen)
        self.assertIn("SupportedLanguages.options",screen)
        self.assertIn("onSelect(option.tag)",screen)
        self.assertIn("LazyColumn(",screen)

if __name__=="__main__":
    unittest.main()
