import base64,copy,json,subprocess,sys,unittest
from pathlib import Path
from unittest.mock import patch
from decoders.Python.apps.Speicers_Turbo_VPN import codec,server_catalog_decoder as cli
ROOT=Path(__file__).resolve().parents[1];DOSSIER=ROOT/'analysis/netfree.mx.anuncios/217';sys.path.insert(0,str(DOSSIER/'tools'))
from make_vectors import seal,oracle
from literal_arrays import evaluate
class SpeicersTurboTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle=(DOSSIER/'tests/fixtures/bundle.json').read_bytes();cls.expected=json.loads((DOSSIER/'tests/fixtures/expected.json').read_text());cls.wire=json.loads((DOSSIER/'tests/fixtures/wire.json').read_text());cls.servers=(DOSSIER/'tests/fixtures/servers.txt').read_bytes();cls.users=(DOSSIER/'tests/fixtures/users.txt').read_bytes()
    def test_complete_pair_all_fields_and_unknown_metadata(self):
        self.assertEqual(json.loads(cli.run(self.bundle)),self.expected);self.assertEqual(codec.decode_catalog(self.servers),self.expected['catalogs']['servers']);self.assertEqual(codec.decode_catalog(self.users),self.expected['catalogs']['users']);self.assertEqual(codec.decode_field(''),'')
    def test_independent_jca_entire_fixture(self):
        for name,raw,section,fields in [('servers',self.servers,'Servers',codec.SERVER_FIELDS),('users',self.users,'Usuarios',codec.USER_FIELDS)]:
            doc=json.loads(oracle('O',codec.CATALOG_PASSWORD,[raw])[0]);row=doc[section][0];keys=sorted(fields&row.keys());values=oracle('F',codec.FIELD_KEY,[row[k].encode() for k in keys])
            for k,v in zip(keys,values):row[k]=v.decode()
            self.assertEqual(doc,self.expected['catalogs'][name])
    def test_worker_and_cli_file_stdin_whole_pair(self):
        from cloud.workers.python.engine import decode_provider_catalog
        worker=decode_provider_catalog('speicers-turbo-vpn',self.bundle);self.assertEqual(worker['structuredJson'],self.expected);self.assertEqual(json.loads(worker['rawText']),self.expected);self.assertFalse(worker['isPartial']);self.assertFalse(worker['exporterCertified'])
        for args in [[str(DOSSIER/'tests/fixtures/bundle.json')],['--stdin']]:
            p=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/Speicers_Turbo_VPN/server_catalog_decoder.py'),*args],input=self.bundle,capture_output=True,check=True);self.assertEqual(json.loads(p.stdout),self.expected)
    def test_invalid_outer_padding_header_and_bounds(self):
        for raw in [b'',b'<html>denied</html>',b'%%%%',self.servers[:-3],b'A'*(codec.MAX_BYTES+1)]:
            with self.assertRaises(ValueError):codec.decode_catalog(raw)
        wrong=oracle('E',b'fictional wrong password',[json.dumps(self.wire['servers']).encode()])[0]
        with self.assertRaises(ValueError):codec.decode_catalog(wrong)
    def test_bad_inner_value_cannot_be_returned_as_plaintext(self):
        for value in ['not-a-ciphertext',base64.urlsafe_b64encode(bytes(33)).decode(),None,1]:
            wire=copy.deepcopy(self.wire['servers']);wire['Servers'][0]['U7V8DoP4cYkXJjCnpqW6nQ==']=value
            with self.assertRaises(ValueError):codec.decode_catalog(seal(wire))
    def test_schema_duplicates_and_nonfinite(self):
        invalid=[{'Version':1},{'Servers':[]},{'Servers':[{}]},{'ReleaseNotes':{}},{'Usuarios':[{'Name':'wrong-section'}]}];docs=[json.dumps({**self.wire['servers'],**x}).encode() for x in invalid];docs.extend([b'{"Version":"a","Version":"b"}',b'[]',b'{"Version":"a","Servers":[],"number":NaN}'])
        for raw in oracle('E',codec.CATALOG_PASSWORD,docs):
            with self.assertRaises(ValueError):codec.decode_catalog(raw)
    def test_pair_requires_both_exact_source_documents(self):
        for sources in [{'servers':self.servers},{'servers':self.users,'users':self.servers}]:
            b={'kind':cli.BUNDLE_KIND,'catalogs':{k:base64.b64encode(v).decode() for k,v in sources.items()}}
            with self.assertRaises(ValueError):cli.run(json.dumps(b).encode())
        for raw in [b'{"kind":1,"kind":2,"catalogs":{}}',b'{"kind":"wrong","catalogs":{}}']:
            with self.assertRaises(ValueError):cli.run(raw)
    def test_fixed_source_requests_and_original_unoverridden_agent_profile(self):
        parent=self
        class Reply:
            status=200;headers={}
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,n):parent.assertEqual(n,codec.MAX_BYTES+1);return parent.servers
        class Opener:
            def open(self,req,timeout):
                parent.assertEqual(req.get_method(),'GET');parent.assertIn(req.full_url,[cli.CATALOG_URL,cli.USERS_URL]);parent.assertEqual(req.get_header('User-agent'),'Dalvik/2.1.0 (Linux; U; Android 14)');parent.assertIsNone(req.get_header('Authorization'));return Reply()
        with patch.object(cli,'build_opener',return_value=Opener()):self.assertEqual(cli.download(),self.servers);self.assertEqual(cli.download(users=True),self.servers)
    def test_redirect_html_and_network_fail_closed(self):
        with self.assertRaises(ValueError):cli._NoRedirect().redirect_request(None,None,302,'',{},cli.CATALOG_URL)
        with patch.object(cli,'build_opener',side_effect=OSError('network')):
            with self.assertRaises(ValueError):cli.download()
        p=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/Speicers_Turbo_VPN/server_catalog_decoder.py'),'--stdin'],input=b'<html>private-marker</html>',capture_output=True);self.assertEqual(p.returncode,1);self.assertEqual(p.stdout,b'');self.assertNotIn(b'private-marker',p.stderr)
    def test_arithmetic_recovery_parser_has_java_unsigned_shift_and_no_eval(self):
        self.assertEqual(evaluate('(byte) ((-1) >>> 24)',{}),-1);self.assertEqual(evaluate('((1 << 31) >>> 31) ^ 2',{}),3);self.assertEqual(evaluate('r1[0] ^ 2',{'r1':[5]}),7)
        for text in ['__import__("os")','open(x)','1;2']:
            with self.assertRaises((ValueError,KeyError,IndexError)):evaluate(text,{})
if __name__=='__main__':unittest.main()
