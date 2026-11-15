"""Synthetic diagnostics, not a claim that build-934 payloads can be decrypted."""
import importlib.util,json,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from tests.golden.http_custom_899 import seal
from decoders.Python.apps.HTTP_Custom import codec

spec=importlib.util.spec_from_file_location('hc934_inventory',Path(__file__).parents[1]/'tools/inventory.py')
inventory=importlib.util.module_from_spec(spec);spec.loader.exec_module(inventory)

class DiagnosticsTests(unittest.TestCase):
    def envelope(self,schema=12,schedule='n15'):
        return {'a':'HCCFG','b':schema,'c':'s1','d':'h1','e':schedule,'h':0,'n':934,
                'g':'private-seed-placeholder','i':{'c':'private-ciphertext-placeholder'},
                'p':{'a':'private-id-placeholder','b':'private-wrap-placeholder','c':'private-hash-placeholder'},
                'j':[{'c':'private-profile-placeholder'}]}

    def test_authenticated_metadata_is_not_plaintext_success(self):
        for schema,schedule in [(12,'n15'),(12,'n16'),(13,'n18')]:
            data=seal(self.envelope(schema,schedule));report=inventory.sample_report(data)
            self.assertTrue(report['outer_authenticated'])
            self.assertEqual(report['metadata']['b'],schema)
            with self.assertRaisesRegex(codec.HCError,'^UNSUPPORTED_SCHEMA$'):codec.decrypt(data)

    def test_diagnostics_do_not_leak_encrypted_or_private_material(self):
        report=inventory.sample_report(seal(self.envelope()))
        self.assertNotIn('private-',json.dumps(report))
        self.assertEqual(report['extra_protection_shape'],['a','b','c'])

    def test_tampered_and_truncated_outer_envelopes_are_rejected(self):
        data=seal(self.envelope())
        for bad in (data[:39],data[:-1]+bytes([data[-1]^1])):
            with self.assertRaises(codec.HCError):inventory.sample_report(bad)

if __name__=='__main__':unittest.main()
