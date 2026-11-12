import importlib.util,json,subprocess,sys,unittest,base64
from pathlib import Path
from unittest.mock import patch
from Crypto.Cipher import AES
from decoders.Python.apps.HTTP_Conexion import codec,server_catalog_decoder as cli
ROOT=Path(__file__).resolve().parents[1];DOSSIER=ROOT/'analysis/com.doriaxvpn.unlimited/129'
spec=importlib.util.spec_from_file_location('http_conexion_vectors',DOSSIER/'tools/make_vectors.py')
vectors=importlib.util.module_from_spec(spec);spec.loader.exec_module(vectors)
class HttpConexionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(DOSSIER/'tests/fixtures/catalog.txt').read_bytes()
        cls.expected=json.loads((DOSSIER/'tests/fixtures/expected.json').read_text())
        cls.wire=json.loads((DOSSIER/'tests/fixtures/wire.json').read_text())
    def test_full_jca_fixture_preserves_metadata_unicode_and_all_fields(self):
        self.assertEqual(codec.decode_catalog(self.data),self.expected)
        self.assertEqual(set(codec.GCM_FIELDS),set(json.loads((DOSSIER/'generated/protected-fields.json').read_text())))
        self.assertEqual(codec.decode_catalog(self.data)['Servers'][0]['ServerPort'],'443')
    def test_wrapped_base64_inside_and_outside_gcm_and_rot34(self):
        field=self.wire['Servers'][0]['Payload'];self.assertIn('\n',field)
        raw=base64.b64decode(field);clear=AES.new(codec.FIELD_KEY,AES.MODE_GCM,nonce=raw[:12]).decrypt_and_verify(raw[12:-16],raw[-16:])
        self.assertIn(b'\n',clear)
        self.assertEqual(codec.decode_field(field),self.expected['Servers'][0]['Payload'])
        self.assertEqual(codec.decode_field(self.wire['Servers'][0]['zivpnPassword']),codec.ROT)
    def test_entire_worker_and_cli_file_stdin(self):
        from cloud.workers.python.engine import decode_provider_catalog
        r=decode_provider_catalog('http-conexion',self.data)
        self.assertEqual(r['structuredJson'],self.expected);self.assertEqual(json.loads(r['rawText']),self.expected);self.assertFalse(r['isPartial'])
        for args in [[str(DOSSIER/'tests/fixtures/catalog.txt')],['--stdin']]:
            result=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/HTTP_Conexion/server_catalog_decoder.py'),*args],
              input=self.data,capture_output=True,check=True);self.assertEqual(json.loads(result.stdout),self.expected)
    def test_independent_java_complete_fixture(self):
        clear=vectors.transform('O',[self.data],codec.CATALOG_PASSWORD)[0];wire=json.loads(clear)
        names=[k for k in codec.GCM_FIELDS if wire['Servers'][0].get(k)]
        values=vectors.transform('F',[wire['Servers'][0][k].encode() for k in names],codec.FIELD_KEY)
        for k,v in zip(names,values):wire['Servers'][0][k]=v.decode()
        self.assertEqual(wire,self.expected)
    def test_invalid_outer_and_limits(self):
        for data in [b'',b'<html>denied</html>',b'AAAA','▙'.encode(),self.data[:-7],b'x'*(codec.MAX_INPUT+1)]:
            with self.subTest(length=len(data)),self.assertRaises(ValueError):cli.run(data)
        wrong=vectors.transform('E',[json.dumps(self.wire).encode()],b'wrong-password')[0]
        with self.assertRaises(ValueError):cli.run(wrong)
    def test_bad_gcm_tag_never_falls_back_to_ciphertext(self):
        wire=json.loads(json.dumps(self.wire));raw=bytearray(base64.b64decode(wire['Servers'][0]['ServerIP']));raw[-1]^=1
        wire['Servers'][0]['ServerIP']=base64.b64encode(raw).decode()
        with self.assertRaises(ValueError):cli.run(vectors.seal(wire))
    def test_authenticated_but_invalid_inner_base64_is_rejected(self):
        wire=json.loads(json.dumps(self.wire));nonce=bytes(range(12));c=AES.new(codec.FIELD_KEY,AES.MODE_GCM,nonce=nonce)
        body,tag=c.encrypt_and_digest(b'not-base64!!!');wire['Servers'][0]['ServerIP']=base64.b64encode(nonce+body+tag).decode()
        with self.assertRaises(ValueError):cli.run(vectors.seal(wire))
    def test_schema_duplicate_and_nonfinite_failures(self):
        changes=[{'Servers':[]},{'Version':1},{'Servers':[{}]},{'Servers':['bad']},{'ReleaseNotes':[]}]
        docs=[json.dumps({**self.wire,**x}).encode() for x in changes]
        docs+=[b'{"Version":"a","Version":"b","Servers":[{"Name":"test"}]}',
          b'{"Version":"a","Servers":[{"Name":"test"}],"bad":NaN}',b'[]']
        for data in vectors.transform('E',docs,codec.CATALOG_PASSWORD):
            with self.assertRaises(ValueError):cli.run(data)
        wire=json.loads(json.dumps(self.wire));wire['Servers'][0]['ServerIP']=1
        with self.assertRaises(ValueError):cli.run(vectors.seal(wire))
    def test_original_fixed_get_cachebuster_and_headers(self):
        class Reply:
            status=200;headers={}
            def __enter__(s):return s
            def __exit__(s,*args):pass
            def read(s,size):self.assertEqual(size,codec.MAX_INPUT+1);return self.data
        class Opener:
            def open(s,req,timeout):
                self.assertEqual(req.full_url,cli.SOURCE+'?nocache=1700000000000');self.assertEqual(req.get_method(),'GET')
                for k,v in cli.HEADERS.items():self.assertEqual(req.get_header(k.capitalize()),v)
                self.assertIsNone(req.get_header('Authorization'));return Reply()
        with patch.object(cli.time,'time',return_value=1700000000),patch.object(cli,'build_opener',return_value=Opener()),patch.object(cli,'resolve_config',return_value={'source':cli.SOURCE,'password':codec.CATALOG_PASSWORD.decode()}):
            data,password=codec.unpack_catalog(cli.download());self.assertEqual(data,self.data);self.assertEqual(password,codec.CATALOG_PASSWORD)
    def test_redirect_network_and_cli_no_leak(self):
        with self.assertRaises(ValueError):cli._NoRedirect().redirect_request(None,None,302,'',{},cli.SOURCE)
        with patch.object(cli,'build_opener',side_effect=OSError('network')),patch.object(cli,'resolve_config',return_value={'source':cli.SOURCE,'password':codec.CATALOG_PASSWORD.decode()}):
            with self.assertRaises(ValueError):cli.download()
        r=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/HTTP_Conexion/server_catalog_decoder.py'),'--stdin'],input=b'<html>private-marker</html>',capture_output=True)
        self.assertEqual(r.returncode,1);self.assertEqual(r.stdout,b'');self.assertNotIn(b'private-marker',r.stderr)
if __name__=='__main__':unittest.main()
