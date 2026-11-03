import importlib.util,json,subprocess,sys,unittest
from pathlib import Path
from unittest.mock import patch
from decoders.Python.apps.FNF_TUNNEL_BD import codec,server_catalog_decoder as cli

ROOT=Path(__file__).resolve().parents[1];DOSSIER=ROOT/'analysis/dastan.prince.myvpnksa/35'
def tool(name):
    spec=importlib.util.spec_from_file_location('fnf_'+name,DOSSIER/'tools'/ (name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
seal=tool('make_vectors').seal

class FnfCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(DOSSIER/'tests/fixtures/catalog.txt').read_bytes()
        cls.expected=json.loads((DOSSIER/'tests/fixtures/expected.json').read_text())
    def test_full_vector_preserves_plain_hex_and_unknown_metadata(self):
        self.assertEqual(json.loads(cli.run(self.data)),self.expected)
        self.assertEqual(codec.decode_catalog(self.data)['Payloads'][0]['host'],'80')
    def test_independent_java_entire_document(self):
        self.assertEqual(tool('verify').reference(self.data),self.expected)
    def test_child_worker_entire_document(self):
        from cloud.workers.python.engine import decode_provider_catalog
        r=decode_provider_catalog('fnf-tunnel-bd',self.data)
        self.assertEqual(r['structuredJson'],self.expected);self.assertEqual(json.loads(r['rawText']),self.expected)
        self.assertFalse(r['isPartial']);self.assertEqual(r['warnings'],[])
    def test_cli_file_and_stdin(self):
        script=ROOT/'decoders/Python/apps/FNF_TUNNEL_BD/server_catalog_decoder.py'
        for args in [[str(DOSSIER/'tests/fixtures/catalog.txt')],['--stdin']]:
            r=subprocess.run([sys.executable,str(script),*args],input=self.data,capture_output=True,check=True)
            self.assertEqual(json.loads(r.stdout),self.expected)
    def test_bad_envelopes(self):
        for data in [b'',b'<html>blocked</html>',b'not base64!',self.data[:-7],b'AAAA',b'x'*(codec.MAX_INPUT+1)]:
            with self.subTest(length=len(data)),self.assertRaises(ValueError):cli.run(data)
    def test_corrupt_ciphertext(self):
        data=bytearray(self.data);data[12]=ord('A') if data[12]!=ord('A') else ord('B')
        with self.assertRaises(ValueError):cli.run(bytes(data))
    def test_schema_failures(self):
        for change in [lambda d:d.update(Version=1),lambda d:d.update(Free_servers=[]),
          lambda d:d.update(Payloads=[]),lambda d:d.update(Payloads=[1]),lambda d:d.update(Vip_servers={})]:
            d=json.loads(json.dumps(self.expected));change(d)
            with self.assertRaises(ValueError):cli.run(seal(json.dumps(d)))
    def test_duplicate_nonfinite_nonobject(self):
        for text in ['{"Version":"a","Version":"b","Free_servers":[{}],"Payloads":[{}]}',
          '{"Version":"a","Free_servers":[{}],"Payloads":[{}],"bad":NaN}','[]']:
            with self.assertRaises(ValueError):cli.run(seal(text))
    def test_download_fixed_get(self):
        class Reply:
            status=200;headers={}
            def __enter__(s):return s
            def __exit__(s,*a):pass
            def read(s,size):self.assertEqual(size,codec.MAX_INPUT+1);return self.data
        class Opener:
            def open(s,req,timeout):
                self.assertEqual(req.full_url,cli.SOURCE);self.assertEqual(req.get_method(),'GET')
                self.assertEqual(req.get_header('User-agent'),cli.USER_AGENT)
                self.assertEqual(req.get_header('Accept-encoding'),'identity');return Reply()
        with patch.object(cli,'build_opener',return_value=Opener()):self.assertEqual(cli.download(),self.data)
    def test_redirect_and_network_failures(self):
        with self.assertRaises(ValueError):cli._NoRedirect().redirect_request(None,None,302,'',{},cli.SOURCE)
        with patch.object(cli,'build_opener',side_effect=OSError('network')):
            with self.assertRaises(ValueError):cli.download()
    def test_cli_html_fails_without_sample_leak(self):
        r=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/FNF_TUNNEL_BD/server_catalog_decoder.py'),'--stdin'],
          input=b'<html>private-sample-marker</html>',capture_output=True)
        self.assertEqual(r.returncode,1);self.assertEqual(r.stdout,b'');self.assertNotIn(b'private-sample-marker',r.stderr)
if __name__=='__main__':unittest.main()
