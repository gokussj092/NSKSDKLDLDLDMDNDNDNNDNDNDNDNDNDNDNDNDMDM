import importlib.util,json,subprocess,sys,unittest
from pathlib import Path
from unittest.mock import patch
from decoders.Python.apps.NAMO_VPN import codec,server_catalog_decoder as cli
ROOT=Path(__file__).resolve().parents[1];DOSSIER=ROOT/'analysis/com.appxrayservice.namovpn/35'
spec=importlib.util.spec_from_file_location('namo_vectors',DOSSIER/'tools/make_vectors.py')
vectors=importlib.util.module_from_spec(spec);spec.loader.exec_module(vectors)
class NamoCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(DOSSIER/'tests/fixtures/catalog.txt').read_bytes()
        cls.expected=json.loads((DOSSIER/'tests/fixtures/expected.json').read_text())
    def test_entire_java_fixture_unknown_fields_unicode_and_plaintext(self):
        self.assertEqual(json.loads(cli.run(self.data)),self.expected)
        self.assertEqual(codec.decode_catalog(self.data)['Networks'][0]['UnusualPlainHex'],'deadbeef')
    def test_independent_java_and_all_padding_lengths(self):
        docs=[{**self.expected,'Message':'x'*n} for n in range(4)]
        inputs=[json.dumps(d,ensure_ascii=False).encode() for d in docs]
        for doc,enc in zip(docs,vectors.transform('E',inputs)):self.assertEqual(codec.decode_catalog(enc),doc)
        self.assertEqual(json.loads(vectors.transform('D',[self.data])[0]),self.expected)
    def test_worker_entire_document(self):
        from cloud.workers.python.engine import decode_provider_catalog
        r=decode_provider_catalog('namo-vpn',self.data)
        self.assertEqual(r['structuredJson'],self.expected);self.assertEqual(json.loads(r['rawText']),self.expected)
        self.assertEqual(r['providerId'],'namo-vpn');self.assertFalse(r['isPartial']);self.assertEqual(r['warnings'],[])
    def test_cli_file_and_stdin(self):
        for args in [[str(DOSSIER/'tests/fixtures/catalog.txt')],['--stdin']]:
            r=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/NAMO_VPN/server_catalog_decoder.py'),*args],
              input=self.data,capture_output=True,check=True)
            self.assertEqual(json.loads(r.stdout),self.expected)
    def test_bad_ciphertexts(self):
        for data in [b'',b'<html>denied</html>',b'bad base64!',self.data[:-7],b'AAAA',b'x'*(codec.MAX_INPUT+1)]:
            with self.subTest(length=len(data)),self.assertRaises(ValueError):cli.run(data)
    def test_wrong_key_and_tamper(self):
        wrong=vectors.transform('E',[json.dumps(self.expected).encode()],key=b'wrong-key')[0]
        changed=bytearray(self.data);changed[10]=ord('A') if changed[10]!=ord('A') else ord('B')
        for data in [wrong,bytes(changed)]:
            with self.assertRaises(ValueError):cli.run(data)
    def test_schema_failures(self):
        changes=[{'Servers':[]},{'Networks':[]},{'Version':1},{'Servers':[{}]},
          {'Networks':[{'PayloadName':1}]},{'Message':[]},{'Servers':[1]}]
        docs=[json.dumps({**self.expected,**x}).encode() for x in changes]
        for enc in vectors.transform('E',docs):
            with self.assertRaises(ValueError):cli.run(enc)
    def test_duplicate_nonfinite_nonobject_and_invalid_utf8(self):
        docs=[b'{"Version":"a","Version":"b","Servers":[{}],"Networks":[{}]}',
          b'{"Version":"a","Servers":[{}],"Networks":[{}],"bad":NaN}',b'[]',b'\xff\xfe']
        for enc in vectors.transform('E',docs):
            with self.assertRaises(ValueError):cli.run(enc)
    def test_fixed_get_and_original_agent(self):
        class Reply:
            status=200;headers={}
            def __enter__(s):return s
            def __exit__(s,*a):pass
            def read(s,size):self.assertEqual(size,codec.MAX_INPUT+1);return self.data
        class Opener:
            def open(s,req,timeout):
                self.assertEqual(req.full_url,cli.SOURCE);self.assertEqual(req.get_method(),'GET')
                self.assertEqual(req.get_header('User-agent'),'okhttp/5.3.2')
                self.assertEqual(req.get_header('Accept-encoding'),'identity');self.assertIsNone(req.get_header('Authorization'))
                return Reply()
        with patch.object(cli,'build_opener',return_value=Opener()):self.assertEqual(cli.download(),self.data)
    def test_no_redirect_network_error_and_cli_no_leak(self):
        with self.assertRaises(ValueError):cli._NoRedirect().redirect_request(None,None,302,'',{},cli.SOURCE)
        with patch.object(cli,'build_opener',side_effect=OSError('network')):
            with self.assertRaises(ValueError):cli.download()
        r=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/NAMO_VPN/server_catalog_decoder.py'),'--stdin'],
          input=b'<html>private-marker</html>',capture_output=True)
        self.assertEqual(r.returncode,1);self.assertEqual(r.stdout,b'');self.assertNotIn(b'private-marker',r.stderr)
if __name__=='__main__':unittest.main()
