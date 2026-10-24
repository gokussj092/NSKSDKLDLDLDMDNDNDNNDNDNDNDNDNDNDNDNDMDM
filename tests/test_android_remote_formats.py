"""Release guards for Android remote formats, sanitized assets and localized notices."""
import json
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

from scripts.android_a24_catalog import generate

ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/"android/app/src/main"
JAVA=APP/"java/com/ghostdeveloper/spdecode"
LOCALES=("values","values-es","values-fr","values-de","values-in",
    "values-pt-rBR","values-ru","values-fa","values-ar","values-tr",
    "values-vi","values-hi","values-ja","values-it")


class RemoteFormatsAndroidTests(unittest.TestCase):
    def test_public_apk_asset_has_no_python_script_or_server_routing(self):
        text=(APP/"assets/decoder_catalog.json").read_text("utf-8")
        record=json.loads(text)
        self.assertEqual(record["schemaVersion"],4)
        self.assertEqual(len(record["entries"]),239)
        for forbidden in ('"script"', '"originalRuntime"', '"sourceCatalog"',
                          "decoders/Python/", '"inventorySource"'):
            self.assertNotIn(forbidden,text)
        keys={"suffix","name","androidPortStatus","androidVerified","migrationPhase"}
        self.assertTrue(all(set(item)==keys for item in record["entries"]))

    def test_native_e_f_family_suffixes_retain_original_routing(self):
        router=(JAVA/"parity/AndroidOfflineDecoderRouter.kt").read_text("utf-8")
        self.assertNotIn("format.script",router)
        self.assertNotIn("decoders/Python/",router)
        full=generate()["entries"]
        e=[x for x in full if x["migrationPhase"]=="E"]
        f=[x for x in full if x["migrationPhase"]=="F"]
        e1={"sentinel.py","itv.py","eut.py","v2box_export.py",
            "slipnet.py","juanscript.py"}
        expected_e1={x["suffix"] for x in e if x["script"].split("/")[-1] in e1}
        expected_e3={x["suffix"] for x in e if x["script"].endswith("xor_family.py")}
        expected_f1={x["suffix"] for x in f if x["script"].split("/")[-1] in
                     {"flex.py","ltm.py","vn7.py"}}
        expected_f2={x["suffix"] for x in f if x["script"].split("/")[-1] in
                     {"crev.py","zoba.py","n4.py","dev.py","ktr.py"}}
        block_e=router.split('if (format.migrationPhase == "E")')[1].split(
            'if (format.migrationPhase == "F")')[0]
        block_f=router.split('if (format.migrationPhase == "F")')[1].split(
            'return when (format.suffix) {',1)[1].split('}',1)[0]
        def group(text,decoder):
            match=re.search(r'((?:"[^"]+"[\s,]*)+)->\s*'+decoder,text)
            self.assertIsNotNone(match,decoder)
            return set(re.findall(r'"([^"]+)"',match.group(1)))
        self.assertEqual(group(block_e,"SpecialE3Port.decode"),expected_e3)
        self.assertEqual(group(block_e,"SpecialE1Port.decode"),expected_e1)
        self.assertEqual(group(block_f,"IndependentF1Port.decode"),expected_f1)
        self.assertEqual(group(block_f,"IndependentF2Port.decode"),expected_f2)
        self.assertIn('"izph" -> IzphNativePort.decode',block_f)
        self.assertEqual(len(e),27)
        self.assertEqual(len(f),13)

    def test_cached_snapshot_is_versioned_and_fail_closed(self):
        repo=(JAVA/"cloud/ServerVpnCatalogRepository.kt").read_text("utf-8")
        for check in ("formatsSchemaVersion","formatDetection","formatCount",
                      "cachedFormats()","hasCachedFormats()","seen.add(suffix)",
                      'entry.getString("kind")=="file"',
                      'entry.getBoolean("cloudSupported")',
                      'vault.write("catalog",fresh'):
            self.assertIn(check,repo)
        activity=(JAVA/"MainActivity.kt").read_text("utf-8")
        for check in ("AndroidDecoderCatalog.detect(routingName,fileFormats)",
                      "serverVpnCatalog.cachedFormats()",
                      "R.string.file_extension_unsupported_contact",
                      "R.string.text_format_unsupported_contact",
                      "CloudUserErrors.httpInjectorMessage"):
            self.assertIn(check,activity)

    def test_14_locales_have_specific_notices_with_matching_keys(self):
        for locale in LOCALES:
            with self.subTest(locale=locale):
                base=APP/"res"/locale
                a=ET.parse(base/"remote_formats_strings.xml").getroot()
                b=ET.parse(base/"http_injector_errors.xml").getroot()
                strings={node.attrib["name"] for node in a}
                self.assertEqual(strings,{
                    "file_extension_unsupported_contact",
                    "text_format_unsupported_contact",
                    "formats_remote_catalog_note",
                    "formats_cloud_ready_short"})
                self.assertTrue(all((node.text or "").strip() for node in a))
                self.assertEqual({node.attrib["name"] for node in b},
                    {"cloud_http_injector_not_configured"})
                self.assertTrue(all((node.text or "").strip() for node in b))

    def test_no_generic_error_on_unknown_file_text_or_injector_setup(self):
        client=(JAVA/"cloud/CloudUserErrors.kt").read_text("utf-8")
        self.assertIn('"REMOTE_NOT_CONFIGURED" -> R.string.cloud_http_injector_not_configured',client)
        self.assertIn('"UNSUPPORTED_FORMAT" -> R.string.cloud_failure_unsupported',client)
        activity=(JAVA/"MainActivity.kt").read_text("utf-8")
        self.assertIn("unsupportedNotice && inputs.size==1",activity)
        self.assertIn("messageIsCredentialNotice=true",activity)


if __name__=="__main__":
    unittest.main()
