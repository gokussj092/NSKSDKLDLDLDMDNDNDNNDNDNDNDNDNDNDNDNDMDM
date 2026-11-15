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
        inputs=[json.dumps(vectors.transform_fields(d,'E'),ensure_ascii=False).encode() for d in docs]
        for doc,enc in zip(docs,vectors.transform('E',inputs)):self.assertEqual(codec.decode_catalog(enc),doc)
        self.assertEqual(vectors.transform_fields(json.loads(vectors.transform('D',[self.data])[0])),self.expected)
    def test_inner_fields_are_really_encoded_in_java_fixture(self):
        outer=json.loads(vectors.transform('D',[self.data])[0])
        for group,fields in [('Servers',codec.SERVER_FIELDS),('Networks',codec.NETWORK_FIELDS)]:
            for key in fields:
                self.assertNotEqual(outer[group][0][key],self.expected[group][0][key])
        self.assertNotEqual(outer['setOpenVPN'],self.expected['setOpenVPN'])
    def test_decode_once_and_preserve_metadata_and_string_types(self):
        doc=json.loads(json.dumps(self.expected));doc['Servers'][0]['Username']='dGVzdA=='
        enc=vectors.transform('E',[json.dumps(vectors.transform_fields(doc,'E')).encode()])[0]
        out=codec.decode_catalog(enc);self.assertEqual(out,doc)
        self.assertEqual(out['Networks'][0]['FutureBase64'],'cHJlc2VydmU=')
        self.assertEqual(out['Servers'][0]['TCPPort'],'443')
    def test_inner_empty_missing_and_unpadded(self):
        doc=vectors.transform_fields(self.expected,'E')
        doc['Servers'][0]['Password']='';del doc['Servers'][0]['ProxyIP']
        doc['Networks'][0]['Sni']='ZnJvbnQuZXhhbXBsZS5vcmc' # unpadded
        out=codec.decode_catalog(vectors.transform('E',[json.dumps(doc).encode()])[0])
        self.assertEqual(out['Servers'][0]['Password'],'');self.assertNotIn('ProxyIP',out['Servers'][0])
        self.assertEqual(out['Networks'][0]['Sni'],'front.example.org')
    def test_inner_corruption_type_and_utf8_fail_closed(self):
        base=vectors.transform_fields(self.expected,'E');docs=[]
        for group,key in [('Servers','ServerIP'),('Networks','Payload'),(None,'setOpenVPN')]:
            for bad in ['bad!', 'A', 'YQ===', 'YQ=x', 'YQ=', '\n ', '/w==', 'ไทย', 1, None, []]:
                doc=json.loads(json.dumps(base))
                (doc[group][0] if group else doc)[key]=bad
                docs.append(json.dumps(doc).encode())
        for i,enc in enumerate(vectors.transform('E',docs)):
            with self.subTest(case=i),self.assertRaises(ValueError):codec.decode_catalog(enc)
    def test_worker_entire_document(self):
        from cloud.workers.python.engine import decode_provider_catalog
        r=decode_provider_catalog('namo-vpn',self.data)
        self.assertEqual(r['structuredJson'],self.expected);self.assertEqual(json.loads(r['rawText']),self.expected)
        self.assertEqual(r['providerId'],'namo-vpn');self.assertFalse(r['isPartial']);self.assertEqual(r['warnings'],[])
    def test_worker_rejects_bad_inner_field_without_partial_result(self):
        from cloud.workers.python.engine import decode_provider_catalog,DecodeFailure
        doc=vectors.transform_fields(self.expected,'E');doc['Networks'][0]['Payload']='private-marker!'
        data=vectors.transform('E',[json.dumps(doc).encode()])[0]
        with self.assertRaises(DecodeFailure) as result:decode_provider_catalog('namo-vpn',data)
        self.assertNotIn('private-marker',str(result.exception))
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
