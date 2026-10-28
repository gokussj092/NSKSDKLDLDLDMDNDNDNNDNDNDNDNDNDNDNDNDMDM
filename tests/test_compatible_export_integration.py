"""Release and privacy boundaries for the cross-layer export integration."""
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'android/app'

class CompatibleExportIntegration(unittest.TestCase):
    def test_release_metadata_and_workflow_artifacts_agree(self):
        gradle=(APP/'build.gradle.kts').read_text()
        version=re.search(r'versionName = "([^"]+)"',gradle)[1]
        code=re.search(r'versionCode = (\d+)',gradle)[1]
        self.assertRegex(version,r'^\d+\.\d+\.\d+
        private=(ROOT/'.github/workflows/cloud-private-preproduction-apk.yml').read_text()
        play=(ROOT/'.github/workflows/play-beta-artifacts.yml').read_text()
        public=(ROOT/'.github/workflows/cloud-preproduction-public.yml').read_text()
        for source in (private,play,public):
            self.assertIn(f"versionName='{version}'",source)
            self.assertIn(f"versionCode='{code}'",source)
            self.assertIn('SP-DECODE-v'+version,source)
        workflow=(ROOT/'.github/workflows/compatible-export-integration.yml').read_text()
        self.assertIn(':app:compileDebugKotlin',workflow)
        self.assertIn(':app:compileDebugAndroidTestKotlin',workflow)
        for forbidden in ('assemble','bundleRelease','gh release','SPDECODE_SIGNING_'):
            self.assertNotIn(forbidden,workflow)

    def test_each_supported_locale_has_export_messages(self):
        required={'compatible_export_for','compatible_export_redecode','compatible_export_failed'}
        for path in (APP/'src/main/res').glob('values*/strings.xml'):
            resource=path.parent/'compatible_export_strings.xml'
            self.assertTrue(resource.is_file(),path.parent.name)
            items=ET.parse(resource).getroot().findall('string')
            self.assertEqual({i.attrib['name'] for i in items},required)
            self.assertTrue(all((i.text or '').strip() for i in items))

    def test_storage_uses_encrypted_history_and_export_writes_binary(self):
        history=(APP/'src/main/java/com/ghostdeveloper/spdecode/SecureDecodeHistory.kt').read_text()
        button=(APP/'src/main/java/com/ghostdeveloper/spdecode/cloud/CompatibleExportButton.kt').read_text()
        self.assertIn('record.compatibleExport',history)
        self.assertIn('AES/GCM/NoPadding',history)
        self.assertIn('noBackupFilesDir',history)
        self.assertIn('version in 1..3',history)
        self.assertIn('out.write(bytes)',button)
        self.assertIn('artifact.matches(entry.rawText)',button)
        self.assertNotIn('ResultPresentation',button)
        self.assertNotIn('writeText',button)
        self.assertIn('CancellationException',button)

if __name__=='__main__':unittest.main()
)
        self.assertGreaterEqual(int(code),33)
        private=(ROOT/'.github/workflows/cloud-private-preproduction-apk.yml').read_text()
        play=(ROOT/'.github/workflows/play-beta-artifacts.yml').read_text()
        public=(ROOT/'.github/workflows/cloud-preproduction-public.yml').read_text()
        for source in (private,play,public):
            self.assertIn(f"versionName='{version}'",source)
            self.assertIn(f"versionCode='{code}'",source)
            self.assertIn('SP-DECODE-v'+version,source)
        workflow=(ROOT/'.github/workflows/compatible-export-integration.yml').read_text()
        self.assertIn(':app:compileDebugKotlin',workflow)
        self.assertIn(':app:compileDebugAndroidTestKotlin',workflow)
        for forbidden in ('assemble','bundleRelease','gh release','SPDECODE_SIGNING_'):
            self.assertNotIn(forbidden,workflow)

    def test_each_supported_locale_has_export_messages(self):
        required={'compatible_export_for','compatible_export_redecode','compatible_export_failed'}
        for path in (APP/'src/main/res').glob('values*/strings.xml'):
            resource=path.parent/'compatible_export_strings.xml'
            self.assertTrue(resource.is_file(),path.parent.name)
            items=ET.parse(resource).getroot().findall('string')
            self.assertEqual({i.attrib['name'] for i in items},required)
            self.assertTrue(all((i.text or '').strip() for i in items))

    def test_storage_uses_encrypted_history_and_export_writes_binary(self):
        history=(APP/'src/main/java/com/ghostdeveloper/spdecode/SecureDecodeHistory.kt').read_text()
        button=(APP/'src/main/java/com/ghostdeveloper/spdecode/cloud/CompatibleExportButton.kt').read_text()
        self.assertIn('record.compatibleExport',history)
        self.assertIn('AES/GCM/NoPadding',history)
        self.assertIn('noBackupFilesDir',history)
        self.assertIn('version in 1..3',history)
        self.assertIn('out.write(bytes)',button)
        self.assertIn('artifact.matches(entry.rawText)',button)
        self.assertNotIn('ResultPresentation',button)
        self.assertNotIn('writeText',button)
        self.assertIn('CancellationException',button)

if __name__=='__main__':unittest.main()
