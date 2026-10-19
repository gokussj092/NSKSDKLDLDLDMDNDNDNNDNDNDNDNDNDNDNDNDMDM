"""APK audit must distinguish Android-generated baseline profiles from secrets."""
from __future__ import annotations
import pathlib,subprocess,tempfile,unittest,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
AUDIT=ROOT/"tests/cloud_c5_apk_audit.py"
class CloudSignedAPKAuditTests(unittest.TestCase):
    def audit(self,extra_assets=(),dex_content=b"FAKE DEX FOR TEST ONLY"):
        with tempfile.TemporaryDirectory() as folder:
            apk=pathlib.Path(folder)/"test.apk"
            with zipfile.ZipFile(apk,"w") as z:
                z.writestr("lib/arm64-v8a/libspdecode.so",b"test native")
                z.writestr("classes.dex",dex_content)
                z.writestr("assets/decoder_catalog.json","{}")
                for name in extra_assets:z.writestr(name,b"synthetic")
            return subprocess.run(["python3",str(AUDIT),str(apk)],
                                  cwd=ROOT,capture_output=True,text=True)
    def test_debug_catalog_allowed(self):
        self.assertEqual(self.audit().returncode,0)
    def test_release_optimizer_profiles_allowed(self):
        self.assertEqual(self.audit(("assets/dexopt/baseline.prof",
                                     "assets/dexopt/baseline.profm")).returncode,0)
    def test_unknown_asset_denied(self):
        result=self.audit(("assets/provider-secret.json",))
        self.assertNotEqual(result.returncode,0)
        self.assertIn("Unexpected bundled assets",result.stderr)
    def test_vault_denied(self):
        result=self.audit(("assets/embedded_kotlin_profiles.json.spv",))
        self.assertNotEqual(result.returncode,0)
    def test_embedded_legacy_class_denied(self):
        result=self.audit(dex_content=b"xxxparity/SecureAssetVault;xxx")
        self.assertNotEqual(result.returncode,0)
if __name__=="__main__":unittest.main()
