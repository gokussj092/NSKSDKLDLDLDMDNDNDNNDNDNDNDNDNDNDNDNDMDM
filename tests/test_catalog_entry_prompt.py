"""Foreground VPS catalog announcements require confirmation and translations."""
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def read(path):return (ROOT/path).read_text(encoding="utf-8")
class CatalogOfferContractTests(unittest.TestCase):
 def test_server_version_is_checked_on_entry_not_auto_downloaded(self):
  activity=read("android/app/src/main/java/com/ghostdeveloper/spdecode/MainActivity.kt")
  self.assertIn("val remote=cloudClient.watchCatalogVersion(0)",activity)
  self.assertIn("offerServerCatalogVersion(remote)",activity)
  self.assertIn("CloudLegalConsent.accepted",read("android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudCatalogUpdates.kt"))
  self.assertIn("client.watchCatalogVersion(known)",read("android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudCatalogUpdates.kt"))
  self.assertIn("onConfirmServerVpnUpdate={confirmServerVpnUpdate()}",activity)
  self.assertIn("val apps=serverVpnCatalog.refreshIfDue(",activity)
  self.assertIn("last_dismissed_catalog_until",activity)
  self.assertIn("catalogPostponeMillis=24L*60*60*1000",activity)
  self.assertIn("probeUpdatesOnEntry()",activity)
 def test_cancel_requires_second_confirmation(self):
  ui=read("android/app/src/main/java/com/ghostdeveloper/spdecode/SpDecodeApp.kt")
  self.assertIn("confirmCatalogPostpone",ui)
  self.assertIn("R.string.catalog_postpone_body",ui)
  self.assertIn("R.string.catalog_offer_body",ui)
  self.assertIn("R.string.catalog_offer_update",ui)
 def test_all_14_locales_have_identical_prompt_contract(self):
  keys={"catalog_offer_title","catalog_offer_body","catalog_offer_update","catalog_offer_later",
  "catalog_postpone_title","catalog_postpone_body","catalog_postpone_confirm","catalog_postpone_back"}
  dirs=("values","values-es","values-pt-rBR","values-fr","values-de","values-it",
      "values-tr","values-ru","values-ar","values-fa","values-hi","values-ja","values-in","values-vi")
  for dir in dirs:
   path=ROOT/"android/app/src/main/res"/dir/"catalog_offer_strings.xml"
   root=ET.parse(path).getroot()
   found={item.attrib["name"]:item.text for item in root.findall("string")}
   self.assertEqual(set(found),keys,dir)
   self.assertTrue(all(found.values()),dir)
   self.assertEqual(found["catalog_offer_body"].count("%1$d"),1,dir)
if __name__=="__main__":unittest.main()
