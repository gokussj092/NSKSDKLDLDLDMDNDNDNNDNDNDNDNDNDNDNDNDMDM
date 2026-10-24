"""Focused independent JDK vectors, RENZ compatibility and isolated Cloud."""
import base64,json,subprocess,sys,unittest
from pathlib import Path
from decoders.Python.apps.Xhypher_Tunnel_Pro import codec,server_catalog_decoder as catalog,file_decoder
from decoders.Python import renz
from cloud.workers.python.engine import decode_provider_catalog
ROOT=Path(__file__).resolve().parents[1]

class XhypherSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v=json.loads((ROOT/'tests/golden/xhypher_tunnel_pro_vectors.json').read_text());cls.raw=cls.v['catalog'].encode()
    def test_full_jdk_document_cli_and_actual_isolated_worker(self):
        self.assertEqual(json.loads(catalog.run(self.raw)),self.v['expected'])
        result=decode_provider_catalog('xhypher-tunnel-pro',self.raw)
        self.assertEqual(result['structuredJson'],self.v['expected']);self.assertEqual(json.loads(result['rawText']),self.v['expected']);self.assertFalse(result['isPartial'])
        path=ROOT/'decoders/Python/apps/Xhypher_Tunnel_Pro/server_catalog_decoder.py'
        p=subprocess.run([sys.executable,str(path),'--stdin'],input=self.raw,cwd='/tmp',capture_output=True,check=True)
        self.assertEqual(json.loads(p.stdout),self.v['expected'])
    def test_invisible_credentials_and_zero_ciphertext_boundary(self):
        self.assertEqual(codec.decode_sensitive(self.v['invisibleSample']),self.v['invisibleExpected'])
        b=self.v['boundary'];self.assertEqual(codec.decode_special(b['cipher']),b['plain']);self.assertEqual(renz.renz_decrypt_speciale(b['cipher'],'xhypher'),b['plain'])
        for invalid in ['\u200b','\u200d','\u200b'*8+'x']:
            with self.assertRaises(ValueError):codec.decode_invisible(invalid)
        with self.assertRaises(ValueError):codec.decode_special(base64.b64encode(b'incomplete').decode())
    def test_corruption_rejects_entire_catalog_and_limits(self):
        for invalid in [b'',b'<html/>',b'x'*(codec.MAX_BYTES+1),self.raw[:-5],self.v['invalidFieldCatalog'].encode()]:
            with self.subTest(length=len(invalid)),self.assertRaises(codec.DecodeError):catalog.run(invalid)
        with self.assertRaises(codec.DecodeError):catalog._NoRedirect().redirect_request(None,None,None,None,None,None)
    def test_existing_file_text_routes_and_historical_data(self):
        raw=self.v['file'].encode()
        self.assertEqual(json.loads(file_decoder.run(raw))['config'],self.v['expectedFile'])
        self.assertEqual(json.loads(renz.decode_file(raw,'.xhypher'))['config'],self.v['expectedFile'])
        self.assertEqual(json.loads(renz.decode_text('xhyphertunnelpro://'+raw.decode()))['config'],self.v['expectedFile'])
        self.assertEqual(json.loads(renz.decode_file(self.v['historical'].encode(),'.xhypher'))['config'],{'Host':'legacy.example.test','Port':443,'Enabled':False})
        p=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/Xhypher_Tunnel_Pro/file_decoder.py')],input=raw,cwd='/tmp',capture_output=True,check=True)
        self.assertEqual(json.loads(p.stdout)['config'],self.v['expectedFile'])

if __name__=='__main__':unittest.main()
