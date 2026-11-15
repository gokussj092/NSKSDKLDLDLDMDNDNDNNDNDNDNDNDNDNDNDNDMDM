import json,unittest
from pathlib import Path
class AuditReportTests(unittest.TestCase):
    def test_identity_bound_inventory_has_no_authentication_success_claim(self):
        root=Path(__file__).resolve().parents[1]
        identity=json.loads((root/'generated/identity.json').read_text())
        report=json.loads((root/'generated/hmac-usage-summary.json').read_text())
        self.assertEqual(identity['package'],'com.evozi.injector');self.assertEqual(identity['versionCode'],244)
        self.assertEqual(report['baseApkSha256'],identity['baseApkSha256'])
        self.assertTrue(report['scanCompleted']);self.assertFalse(report['credentialMaterialExtracted'])
        self.assertFalse(report['apkCodeExecuted']);self.assertEqual(report['vpnConnectionAuthenticationHmac'],'UNCONFIRMED')
