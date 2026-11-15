"""Build15 lower-case field map; older build13 golden tests remain unchanged."""
import json,unittest
from pathlib import Path
from decoders.Python.apps.AustroPlus_VPN import codec,server_catalog_decoder as cli
ROOT=Path(__file__).resolve().parents[1]
V=json.loads((ROOT/'analysis/xyz.tekidoer.austroplus.vpn/15/tests/fixtures/catalog15.json').read_text())
class Austro15Tests(unittest.TestCase):
    def test_lowercase_catalog_preserves_all_records_unknown_fields_and_types(self):
        out=codec.decode_catalog(V['catalog'].encode());self.assertEqual(out,V['expected'])
        self.assertEqual(out['Servers'][0]['server_port'],'22');self.assertEqual(out['Servers'][0]['ssl_port'],443)
        self.assertEqual(out['Servers'][0]['unknown']['base64Looking'],'YWJjZA==');self.assertFalse(out['force_update'])
    def test_new_catalog_uses_fixed_build15_updater(self):
        self.assertEqual(cli.CATALOG_URL,'https://raw.githubusercontent.com/SpkHexX/HexX/refs/heads/main/AustroTunVPN.json')
    def test_malformed_known_fields_and_names_fail_without_partial_output(self):
        for key in ['invalidField','invalidName']:
            with self.subTest(key=key),self.assertRaises(codec.DecodeError):codec.decode_catalog(V[key].encode())
    def test_whole_independent_java_reference_matches_decoder(self):
        import importlib.util,tempfile
        path=ROOT/'analysis/xyz.tekidoer.austroplus.vpn/15/tools/verify.py'
        spec=importlib.util.spec_from_file_location('austro15proof',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        with tempfile.TemporaryDirectory() as folder:
            sample=Path(folder)/'synthetic.bin';sample.write_text(V['catalog']);r=m.verify(sample,False)
        self.assertTrue(r['wholeIndependentJavaParity']);self.assertEqual(r['servers'],2);self.assertEqual(r['tweaks'],2)
    def test_real_isolated_worker_returns_whole_synthetic_document(self):
        from cloud.workers.python.engine import decode_provider_catalog
        r=decode_provider_catalog('austroplus-vpn',V['catalog'].encode())
        self.assertEqual(r['structuredJson'],V['expected']);self.assertEqual(json.loads(r['rawText']),V['expected']);self.assertFalse(r['isPartial'])
if __name__=='__main__':unittest.main()
