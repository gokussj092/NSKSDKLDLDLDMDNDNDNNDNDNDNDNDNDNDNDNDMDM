"""ALSAHER production catalog route: synthetic Java vectors; no real credentials."""
import importlib.util,io,json,subprocess,sys,unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from decoders.Python.apps.ALSAHER_VIP import codec,server_catalog_decoder as catalog
from cloud.workers.python.engine import decode_provider_catalog

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'analysis/com.alsaher.vip/2'
spec=importlib.util.spec_from_file_location('alsaher_verify',BASE/'tools/verify.py')
reference=importlib.util.module_from_spec(spec);spec.loader.exec_module(reference)

class AlsaherTests(unittest.TestCase):
    def setUp(self):
        self.vector=(BASE/'tests/fixtures/catalog.enc').read_bytes()
        self.expected=json.loads((BASE/'tests/fixtures/expected.json').read_text())
        self.outer=json.loads((BASE/'tests/fixtures/outer.json').read_text())

    def seal(self,doc):return reference.oracle('E',[json.dumps(doc,ensure_ascii=False)])[0].encode()

    def test_full_java_vector_including_aliases_and_unicode(self):
        self.assertEqual(codec.decode_catalog(self.vector),self.expected)
        self.assertEqual(json.loads(catalog.run(self.vector)),self.expected)

    def test_original_cipher_field_contexts_and_unknowns_preserved(self):
        doc=codec.decode_catalog(self.vector)
        self.assertEqual(doc['unknownRoot'],self.expected['unknownRoot'])
        self.assertEqual(doc['JSONsettings'],self.expected['JSONsettings'])
        self.assertIs(doc['Servers'][0]['AutoLogIn'],False)
        self.assertEqual(doc['cloud_get_api'],'https://example.org/get')
        self.assertEqual(doc['cloud_post_api'],'https://example.org/post')

    def test_worker_and_cli_preserve_every_record(self):
        result=decode_provider_catalog('alsaher-vip',self.vector)
        self.assertEqual(result['structuredJson'],self.expected)
        self.assertEqual(json.loads(result['rawText']),self.expected)
        self.assertFalse(result['isPartial']);self.assertFalse(result['exporterCertified'])
        script=ROOT/'decoders/Python/apps/ALSAHER_VIP/server_catalog_decoder.py'
        done=subprocess.run([sys.executable,str(script),'--stdin'],input=self.vector,capture_output=True,timeout=10)
        self.assertEqual(done.returncode,0,done.stderr)
        self.assertEqual(json.loads(done.stdout),self.expected)

    def test_rejects_corrupt_html_plain_json_and_truncated_data(self):
        for data in [b'',b'<html>private-sentinel</html>',b'{}',self.vector[:20],b'!!!!']:
            with self.subTest(data=data),self.assertRaises(ValueError) as error:catalog.run(data)
            self.assertNotIn('private-sentinel',str(error.exception))

    def test_rejects_partial_schema_and_invalid_nested_encryption(self):
        for change in [lambda d:d.pop('JSONsettings'),lambda d:d.update(Servers=[]),
                       lambda d:d.update(SSLNetworks='bad'),
                       lambda d:d['Servers'][0].update(ServerIP='invalid')]:
            doc=json.loads(json.dumps(self.outer));change(doc)
            with self.assertRaises(ValueError):catalog.run(self.seal(doc))

    def test_negative_duplicate_json(self):
        data=reference.oracle('E',['{"Version":"1","Version":"2"}'])[0].encode()
        with self.assertRaises(ValueError):catalog.run(data)

    def test_input_bound(self):
        with self.assertRaises(ValueError):catalog.run(b'x'*(codec.MAX_BYTES+1))

    def test_original_get_has_exact_agent_and_no_authorization(self):
        class Response(io.BytesIO):
            status=200;headers={}
        class Opener:
            def open(inner,request,timeout):
                self.assertEqual(request.full_url,catalog.SOURCE)
                self.assertEqual(request.get_method(),'GET')
                self.assertEqual(request.get_header('User-agent'),'okhttp/4.12.0')
                self.assertIsNone(request.get_header('Authorization'))
                self.assertEqual(timeout,30)
                return Response(self.vector)
        with patch.object(catalog,'build_opener',return_value=Opener()):self.assertEqual(catalog.download(),self.vector)

    def test_redirect_unavailable_html_and_encoding_rejected(self):
        with self.assertRaises(ValueError):catalog._NoRedirect().redirect_request(None,None,302,'',{},'https://example.org/')
        class Response(io.BytesIO):status=200;headers={}
        for data,headers in [(b'',{}),(b'<html/>',{}),(self.vector,{'Content-Encoding':'gzip'})]:
            response=Response(data);response.headers=headers
            with patch.object(catalog,'build_opener') as opener:
                opener.return_value.open.return_value=response
                with self.assertRaises(ValueError):catalog.download()
        with patch.object(catalog,'build_opener') as opener:
            opener.return_value.open.side_effect=HTTPError(catalog.SOURCE,404,'private-sentinel',{},None)
            with self.assertRaises(ValueError) as error:catalog.download()
            self.assertNotIn('private-sentinel',str(error.exception))

if __name__=='__main__':unittest.main()
