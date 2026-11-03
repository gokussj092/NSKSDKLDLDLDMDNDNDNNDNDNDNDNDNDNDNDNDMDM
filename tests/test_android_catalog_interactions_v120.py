"""Source contracts for Cloud catalog notices and 14-locale Android update UI."""
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
ANDROID=ROOT/"android/app/src/main"
JAVA=ANDROID/"java/com/ghostdeveloper/spdecode"
RES=ANDROID/"res"
NEW_STRINGS={
 "unsupported_file_title","unsupported_file_detail",
 "unsupported_version_title","unsupported_version_detail",
 "unsupported_text_title","unsupported_text_detail",
 "catalog_check_action","catalog_checking","catalog_downloading",
 "catalog_progress","app_update_title","app_update_body",
 "app_update_open","app_update_close","catalog_available_title",
 "catalog_available_body","catalog_check_short",
}
LOCALES=["values","values-es","values-pt-rBR","values-ar","values-fa",
         "values-fr","values-in","values-ru","values-de","values-tr",
         "values-vi","values-hi","values-ja","values-it"]

class CatalogInteractions(unittest.TestCase):
 def test_all_languages_have_new_translations(self):
  for locale in LOCALES:
   with self.subTest(locale=locale):
    file=RES/locale/"cloud_interaction_strings.xml"
    tree=ET.parse(file)
    labels={x.attrib["name"]:x.text for x in tree.getroot()}
    self.assertEqual(labels.keys(),NEW_STRINGS)
    self.assertTrue(all(labels.values()))
    self.assertIn("%1$d%%",labels["catalog_progress"])

 def test_missing_ciphers_are_not_infrastructure_faults(self):
  service=(ROOT/"cloud/web/lib/c6-ops-store.mjs").read_text("utf-8")
  self.assertIn('INCOMPATIBLE.has(errorCode)',service)
  self.assertIn('errorCode==="DECODE_FAILED"',service)
  activity=(JAVA/"MainActivity.kt").read_text("utf-8")
  self.assertIn("R.string.unsupported_version_detail",activity)
  self.assertIn("R.string.unsupported_file_detail",activity)
  self.assertIn("R.string.unsupported_text_detail",activity)

 def test_catalog_is_foreground_confirmed_and_remote_routed(self):
  activity=(JAVA/"MainActivity.kt").read_text("utf-8")
  update=(JAVA/"cloud/CloudCatalogUpdates.kt").read_text("utf-8")
  repo=(JAVA/"cloud/ServerVpnCatalogRepository.kt").read_text("utf-8")
  self.assertIn("pendingServerVpnCatalogVersion=latest",activity)
  self.assertIn("CloudTextFormats.identify(userText,textRoutes)",activity)
  self.assertIn("serverVpnCatalog.cachedTextFormats()",activity)
  self.assertIn("onProgress={percent->",activity)
  self.assertIn("fun validateTextFormats(",repo)
  self.assertIn('CloudDecodeClient(applicationContext).watchCatalogVersion(0)',update)
  self.assertNotIn('repository.refreshIfDue(announcedVersion=requested)',update)
  self.assertIn("CloudLegalConsent.accepted(context)",update)

 def test_history_no_longer_shows_batch_button(self):
  ui=(JAVA/"SpDecodeApp.kt").read_text("utf-8")
  start=ui.index("private fun HistoryScreen(")
  end=ui.index("private fun ServerVpnScreen(")
  screen=ui[start:end]
  self.assertNotIn("history_import_batch",screen)
  self.assertIn('testTag("server_vpn_manual_refresh")',ui)
  self.assertIn("R.string.catalog_progress",ui)
  self.assertIn('https://t.me/GhostDeve',ui)

if __name__=="__main__":unittest.main()
