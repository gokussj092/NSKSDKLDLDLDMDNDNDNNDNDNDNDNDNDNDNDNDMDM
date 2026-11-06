"""Negative tests for current-source Android metadata and security gates."""
import tempfile
from pathlib import Path
import unittest

from scripts.ci.current_android_contracts import (
    ContractError, check, current_ui_sources, jni_registry, release_metadata
)


class CurrentAndroidContractsTests(unittest.TestCase):
    def test_repository_metadata_and_jni_are_consistent(self):
        info=check()
        self.assertRegex(info["version_name"],r"^\d+\.\d+\.\d+$")
        self.assertGreater(info["version_code"],0)
        self.assertGreater(info["jni_methods"],0)
        self.assertGreater(info["kotlin_sources"],0)

    def test_accepts_next_version_but_rejects_invalid_and_ambiguous_version(self):
        self.assertEqual(release_metadata('versionCode = 100\nversionName = "2.3.4"\n'),("2.3.4",100))
        for invalid in ('versionCode = 0\nversionName = "2.3.4"',
                        'versionCode = 2\nversionName = "bad"',
                        'versionCode = 2\nversionCode = 3\nversionName = "2.3.4"'):
            with self.subTest(invalid=invalid),self.assertRaises(ContractError):
                release_metadata(invalid)

    def test_jni_new_methods_do_not_need_new_fixed_count(self):
        cpp='RegisterNatives(bridge,methods,n); const_cast<char*>("nativeOne")'
        kotlin='@JvmStatic private external fun nativeOne()'
        self.assertEqual(jni_registry(cpp,kotlin),("nativeOne",))
        self.assertEqual(len(jni_registry(cpp+' const_cast<char*>("nativeTwo")',
            kotlin+'\n@JvmStatic private external fun nativeTwo()')),2)
        with self.assertRaises(ContractError):
            jni_registry(cpp+' const_cast<char*>("nativeTwo")',kotlin)
        with self.assertRaises(ContractError):
            jni_registry(cpp+' const_cast<char*>("nativeOne")',kotlin)

    def test_manifest_rejects_cleartext_backup_and_unknown_launcher(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)
            (p/"java/demo").mkdir(parents=True)
            (p/"java/demo/Home.kt").write_text("class Home {}",encoding="utf-8")
            xml=('<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
                 '<application android:allowBackup="false" android:usesCleartextTraffic="false">'
                 '<activity android:name=".Home"><intent-filter>'
                 '<action android:name="android.intent.action.MAIN"/>'
                 '<category android:name="android.intent.category.LAUNCHER"/>'
                 '</intent-filter></activity></application></manifest>')
            (p/"AndroidManifest.xml").write_text(xml,encoding="utf-8")
            self.assertEqual(current_ui_sources(p),1)
            (p/"AndroidManifest.xml").write_text(xml.replace('android:allowBackup="false"','android:allowBackup="true"'),encoding="utf-8")
            with self.assertRaises(ContractError):
                current_ui_sources(p)
            (p/"AndroidManifest.xml").write_text(xml.replace('android:name=".Home"','android:name=".Missing"'),encoding="utf-8")
            with self.assertRaises(ContractError):
                current_ui_sources(p)


if __name__=="__main__":
    unittest.main()
