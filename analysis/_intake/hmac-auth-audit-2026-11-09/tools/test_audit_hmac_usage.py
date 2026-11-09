"""Audit privacy boundary: secret-looking input data never becomes report content."""
import contextlib,hashlib,importlib.util,io,json,tempfile,unittest,zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
SPEC=importlib.util.spec_from_file_location('audit',Path(__file__).with_name('audit_hmac_usage.py'))
AUDIT=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(AUDIT)

class AuditPrivacyTests(unittest.TestCase):
    def fixture(self,path):
        secret='FICTIONAL_DO_NOT_LOG_PRIVATE_TEST_VALUE'
        base=io.BytesIO()
        with zipfile.ZipFile(base,'w') as z:z.writestr('classes.dex',secret)
        bundle=io.BytesIO()
        with zipfile.ZipFile(bundle,'w') as z:z.writestr('base.apk',base.getvalue())
        (path/'base.apk').write_bytes(base.getvalue());(path/'distribution.bin').write_bytes(bundle.getvalue())
        identity=dict(package='test.example',versionCode=1,baseApkSha256=hashlib.sha256(base.getvalue()).hexdigest(),bundleSha256=hashlib.sha256(bundle.getvalue()).hexdigest())
        (path/'identity.json').write_text(json.dumps(identity))
        instruction=SimpleNamespace(get_name=lambda:'invoke-static',get_output=lambda:'Ljavax/crypto/Mac;->init '+secret)
        method=SimpleNamespace(get_instructions=lambda:[instruction])
        cls=SimpleNamespace(get_methods=lambda:[method])
        dex=SimpleNamespace(get_strings=lambda:['HmacSHA256',secret],get_classes=lambda:[cls])
        return secret,dex
    def test_secret_values_absent_from_file_and_stdout(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder);secret,dex=self.fixture(path);stdout=io.StringIO()
            with patch.object(AUDIT,'DEX',return_value=dex),contextlib.redirect_stdout(stdout):AUDIT.scan(path)
            content=(path/'hmac-usage-summary.json').read_text();self.assertNotIn(secret,content+stdout.getvalue())
            doc=json.loads(content);self.assertEqual(doc['algorithmStringCounts']['HmacSHA256'],1)
            self.assertEqual(doc['javaApiInvocationCounts']['macInit'],1)
            self.assertFalse(doc['credentialMaterialExtracted']);self.assertEqual(doc['vpnConnectionAuthenticationHmac'],'UNCONFIRMED')
    def test_changed_input_fails_before_any_claimed_report(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder);self.fixture(path);(path/'base.apk').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'IDENTITY_INPUT_MISMATCH'):AUDIT.scan(path)
            self.assertFalse((path/'hmac-usage-summary.json').exists())
if __name__=='__main__':unittest.main()
