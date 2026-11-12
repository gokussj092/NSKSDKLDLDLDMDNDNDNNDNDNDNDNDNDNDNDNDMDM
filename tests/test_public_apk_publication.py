import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'cloud/infra/vps/apk-publication.py'
spec = importlib.util.spec_from_file_location('apk_publication', SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class PublicApkPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'public'
        self.apk=Path(self.temp.name)/'candidate.apk'
        self.source='a'*40
        self.signer='b'*64

    def candidate(self,pattern):
        self.apk.write_bytes((pattern*1024)[:150000].ljust(150000,b'0'))
        return self.apk

    def publish(self,version,code,pattern=b'APK!'):
        return mod.publish(self.root,'online',self.candidate(pattern),version,code,self.source,self.signer)

    def test_atomic_promotion_previous_only_and_rollback(self):
        first=self.publish('1.1.30',60,b'one')
        self.assertEqual(mod.status(self.root,'online')['current']['sha256'],first['sha256'])
        self.assertIsNone(mod.status(self.root,'online')['previous'])
        second=self.publish('1.1.31',61,b'two')
        self.assertEqual(mod.status(self.root,'online')['current']['sha256'],second['sha256'])
        self.assertEqual(mod.status(self.root,'online')['previous']['sha256'],first['sha256'])
        third=self.publish('1.1.32',62,b'three')
        self.assertEqual(mod.status(self.root,'online')['previous']['sha256'],second['sha256'])
        self.assertNotEqual(mod.status(self.root,'online')['previous']['sha256'],first['sha256'])
        restored=mod.rollback(self.root,'online')
        self.assertEqual(restored['sha256'],second['sha256'])
        self.assertEqual(mod.status(self.root,'online')['previous']['sha256'],third['sha256'])
        folder=self.root/'online'
        self.assertEqual(sorted(x.name for x in (folder/'slots').iterdir()),['a','b'])
        self.assertTrue((folder/'current').is_symlink())

    def test_failed_candidate_preserves_current_and_previous(self):
        original=self.publish('1.2.0',70,b'valid')
        with self.assertRaisesRegex(RuntimeError,'VERSION_OR_SIGNER_MISMATCH'):
            self.publish('1.2.0',70,b'invalid')
        self.assertEqual(mod.status(self.root,'online')['current'],original)
        self.assertIsNone(mod.status(self.root,'online')['previous'])
        with self.assertRaisesRegex(RuntimeError,'VERSION_OR_SIGNER_MISMATCH'):
            mod.publish(self.root,'online',self.candidate(b'new'),'1.2.1',71,self.source,'c'*64)
        self.assertEqual(mod.status(self.root,'online')['current'],original)

    def test_rejects_invalid_channel_and_corrupt_pointer(self):
        with self.assertRaises(ValueError):
            mod.publish(self.root,'../../etc',self.candidate(b'bad'),'1.0.0',1,self.source,self.signer)
        self.publish('1.0.0',42,b'good')
        link=self.root/'online'/'current'
        link.unlink()
        link.symlink_to('../../other')
        with self.assertRaisesRegex(RuntimeError,'INVALID_RELEASE_POINTER'):
            mod.status(self.root,'online')

    def test_signed_publication_script_never_generates_keystore_or_bypasses_ci(self):
        code=(SCRIPT.parent/'android-public-build.sh').read_text()
        self.assertIn('gh api "repos/$PROJECT/actions/runs/$RUN"',code)
        self.assertIn("r['status']=='completed' and r['conclusion']=='success'",code)
        self.assertIn('signing.env',code)
        self.assertIn('apksigner',code)
        self.assertIn('SPDECODE_OFFLINE_NATIVE=true',code)
        self.assertNotIn('keytool -genkeypair',code)
        self.assertNotIn('debug.keystore',code)
        self.assertNotIn('docker system prune',code)

if __name__=='__main__':
    unittest.main()
