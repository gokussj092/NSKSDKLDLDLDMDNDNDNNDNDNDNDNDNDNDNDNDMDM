"""AM fields only: independent vectors, CLI and strict rejection; no catalog claim."""
import base64,json,subprocess,sys,unittest
from pathlib import Path
from decoders.Python.apps.AM_TUNNEL_LITE_VPN import field_decoder as reader
ROOT=Path(__file__).resolve().parents[1]

class AMFields(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.vectors=json.loads((ROOT/'tests/golden/am_tunnel_lite_vectors.json').read_text())['fields']
    def test_all_independent_jdk_fields(self):
        for vector in self.vectors:
            with self.subTest(letters=len(vector['plain'])):
                self.assertEqual(reader.decode_field(vector['cipher']),vector['plain'])
                self.assertEqual(json.loads(reader.run(vector['cipher'].upper().encode()))['field'],vector['plain'])
    def test_modified_utf8_and_preserved_controls(self):
        for vector in self.vectors:self.assertEqual(reader.decode_modified_utf8(base64.b64decode(vector['modifiedUtf8Base64'])),vector['plain'])
        for bad in [b'\0',b'\xc0\x81',b'\xc1\x81',b'\xed\xa0\x80',b'\xe0\x80\x80','🌐'.encode(),b'\xc2',b'\xe2\x82']:
            with self.subTest(raw=bad),self.assertRaises(ValueError):reader.decode_modified_utf8(bad)
    def test_catalogs_invalid_inputs_and_limits_rejected(self):
        for bad in [b'',b'0',b'not-hex',b'00 00',b'{}',b'00'*(reader.MAX_BYTES//2+1)]:
            with self.subTest(length=len(bad)),self.assertRaises(ValueError):reader.run(bad)
    def test_cli_from_outside_checkout(self):
        vector=self.vectors[4]
        result=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/AM_TUNNEL_LITE_VPN/field_decoder.py')],input=vector['cipher'].encode(),capture_output=True,cwd='/tmp',check=True)
        self.assertEqual(json.loads(result.stdout)['field'],vector['plain'])

if __name__=='__main__':unittest.main()
