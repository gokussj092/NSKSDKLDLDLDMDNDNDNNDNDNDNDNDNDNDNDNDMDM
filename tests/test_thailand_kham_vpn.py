import base64,json,unittest
from pathlib import Path
from cloud.workers.python.engine import decode_provider_catalog,DecodeFailure
from decoders.Python.apps.KHAM_VPN import codec as kham
from decoders.Python.apps.Thailand_VPN import codec as thailand
ROOT=Path(__file__).resolve().parents[1]
K=json.loads((ROOT/'analysis/com.khamvpn.net/24/tests/fixtures/vectors.json').read_text())
T=json.loads((ROOT/'analysis/thailand.vpn.globalvpn/3/tests/fixtures/vectors.json').read_text())

class KhamTests(unittest.TestCase):
    def test_java_golden_complete_fields_and_metadata(self):
        self.assertEqual(kham.decode_catalog(K['wire'].encode()),K['plain'])
        self.assertEqual(json.loads(kham.run(K['wire'].encode())),K['plain'])
    def test_negative_envelopes_and_internal_fields(self):
        for raw in [b'',b'<html/>',b'{}',K['wire'][:-3].encode(),K['badField'].encode(),K['emptyNetworks'].encode(),K['wrongKey'].encode()]:
            with self.subTest(size=len(raw)),self.assertRaises(ValueError):kham.run(raw)
    def test_worker_complete_and_failure(self):
        r=decode_provider_catalog('kham-vpn',K['wire'].encode())
        self.assertEqual(r['structuredJson'],K['plain']);self.assertFalse(r['isPartial']);self.assertFalse(r['exporterCertified'])
        with self.assertRaises(DecodeFailure):decode_provider_catalog('kham-vpn',b'<html/>')

class ThailandTests(unittest.TestCase):
    def test_complete_document_preserved(self):
        self.assertEqual(thailand.decode_catalog(T['wire'].encode()),T['plain'])
        self.assertEqual(json.loads(thailand.run(T['wire'].encode())),T['plain'])
    def test_invalid_transport_and_schema(self):
        values=[b'',b'<html>Site Unavailable</html>',b'{}',b'!!!!',T['wire'][:-3].encode()]
        for change in [{'Status':False},{'Servers':[]},{'Servers':[{}]},{'Settings':None}]:
            values.append(base64.b64encode(json.dumps({**T['plain'],**change}).encode()))
        for raw in values:
            with self.subTest(size=len(raw)),self.assertRaises(ValueError):thailand.run(raw)
    def test_duplicate_keys_and_nonfinite_json(self):
        for raw in [b'{"Status":true,"Status":true}',b'{"Status":NaN}']:
            with self.assertRaises(ValueError):thailand.run(base64.b64encode(raw))
    def test_worker_complete_and_failure(self):
        r=decode_provider_catalog('thailand-vpn',T['wire'].encode())
        self.assertEqual(r['structuredJson'],T['plain']);self.assertFalse(r['isPartial'])
        with self.assertRaises(DecodeFailure):decode_provider_catalog('thailand-vpn',b'<html/>')

if __name__=='__main__':unittest.main()
