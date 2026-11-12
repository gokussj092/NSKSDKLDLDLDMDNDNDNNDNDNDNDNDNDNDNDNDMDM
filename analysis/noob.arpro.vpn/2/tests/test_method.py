import json,unittest
from pathlib import Path
class PendingSourceTests(unittest.TestCase):
    def test_html200_is_not_catalog_success(self):
        d=json.loads((Path(__file__).resolve().parents[1]/'generated/download-proof.json').read_text())
        self.assertTrue(d['html']);self.assertTrue(d['siteUnavailable']);self.assertFalse(d['enabled']);self.assertFalse(d['remoteCatalogVerified'])
