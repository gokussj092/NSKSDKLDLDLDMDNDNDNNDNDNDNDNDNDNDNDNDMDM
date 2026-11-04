import copy,json,subprocess,sys,unittest
from pathlib import Path
from unittest.mock import patch
from decoders.Python.apps.CATNET_VPN import codec,server_catalog_decoder as cli
ROOT=Path(__file__).resolve().parents[1];DOSSIER=ROOT/'analysis/net.catnet.vpn/27';FIX=DOSSIER/'tests/fixtures'
class CatnetCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(FIX/'servers.json').read_bytes();cls.expected=json.loads(cls.data)
        cls.preflight=(FIX/'preflight.json').read_bytes()
    def test_whole_independent_node_reference(self):
        ref=subprocess.run(['node',str(DOSSIER/'tools/JsonOracle.mjs'),str(FIX/'servers.json')],capture_output=True,check=True)
        self.assertEqual(codec.decode_catalog(self.data),json.loads(ref.stdout))
    def test_preserves_plain_fields_future_keys_types_and_unicode(self):
        d=codec.decode_catalog(self.data);self.assertEqual(d,self.expected)
        self.assertEqual(d['def_pass_plain'],'YWJjZA==');self.assertIsNone(d['servers'][1]['script'])
        self.assertEqual(d['servers'][0]['Future']['flags'],[True,None,3])
    def test_cli_file_stdin(self):
        for args in [[str(FIX/'servers.json')],['--stdin']]:
            r=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/CATNET_VPN/server_catalog_decoder.py'),*args],
                input=self.data,capture_output=True,check=True);self.assertEqual(json.loads(r.stdout),self.expected)
    def test_worker_full_document(self):
        from cloud.workers.python.engine import decode_provider_catalog
        d=decode_provider_catalog('catnet-vpn',self.data)
        self.assertEqual(d['structuredJson'],self.expected);self.assertEqual(json.loads(d['rawText']),self.expected)
        self.assertFalse(d['isPartial']);self.assertEqual(d['warnings'],[])
    def test_worker_rejects_html_without_leaking(self):
        from cloud.workers.python.engine import decode_provider_catalog,DecodeFailure
        with self.assertRaises(DecodeFailure) as r:decode_provider_catalog('catnet-vpn',b'<html>private-marker</html>')
        self.assertNotIn('private-marker',str(r.exception))
    def test_bad_json_inputs(self):
        for data in [b'',b'[]',b'{}',b'\xff',b'{',b'{"x":NaN}',b'{"x":1,"x":2}',
                     (FIX/'site-unavailable.html').read_bytes(),b'x'*(codec.MAX_INPUT+1)]:
            with self.subTest(size=len(data)),self.assertRaises(ValueError):codec.run(data)
    def test_schema_failures(self):
        changes=[{'success':False},{'success':1},{'servers':[]},{'servers':{}},{'servers':[{}]},
            {'servers':[None]},{'message':None},{'has_defaults':'true'},{'def_pass_plain':None}]
        for change in changes:
            with self.subTest(change=list(change)),self.assertRaises(ValueError):codec.run(json.dumps({**self.expected,**change}).encode())
        for bad in [None,False,0,-1,'1',1.0,9007199254740992]:
            doc=copy.deepcopy(self.expected);doc['servers'][0]['id']=bad
            with self.assertRaises(ValueError):codec.run(json.dumps(doc).encode())
    def mock_opener(self,answers):
        calls=[]
        class Reply:
            status=200;headers={}
            def __init__(s,data):s.data=data
            def __enter__(s):return s
            def __exit__(s,*a):pass
            def read(s,size):return s.data
        class Opener:
            def open(s,request,timeout):
                calls.append(request);return Reply(answers[len(calls)-1])
        return Opener(),calls
    def test_original_preflight_then_fixed_servers_same_installation_headers(self):
        opener,calls=self.mock_opener([self.preflight,self.data])
        with patch.object(cli,'build_opener',return_value=opener):self.assertEqual(cli.download(),self.data)
        self.assertEqual([r.full_url for r in calls],[cli.PREFLIGHT,cli.SOURCE])
        self.assertEqual(calls[0].get_header('X-xj-installation-id'),calls[1].get_header('X-xj-installation-id'))
        for r in calls:
            self.assertEqual(r.get_method(),'GET');self.assertEqual(r.get_header('User-agent'),'okhttp/4.12.0')
            self.assertEqual(r.get_header('X-app-key'),'pussy_vpn');self.assertEqual(r.get_header('X-xj-version-code'),'27')
            self.assertIsNone(r.get_header('X-xj-integrity-token'));self.assertIsNone(r.get_header('Authorization'))
    def test_preflight_stops_if_integrity_required_or_unknown(self):
        for value in [True,None,0,'false']:
            meta=json.dumps({'success':True,'data':{'integrity_required':value}}).encode()
            opener,calls=self.mock_opener([meta])
            with patch.object(cli,'build_opener',return_value=opener),self.assertRaises(ValueError):cli.download()
            self.assertEqual(len(calls),1)
    def test_preflight_maintenance_html_invalid_fail_closed(self):
        for data in [b'<html>maintenance</html>',b'{}',b'[]',b'bad',
            b'{"success":true,"data":{"maintenance":true,"integrity_required":false}}']:
            opener,calls=self.mock_opener([data])
            with patch.object(cli,'build_opener',return_value=opener),self.assertRaises(ValueError):cli.download()
            self.assertEqual(len(calls),1)
    def test_bad_server_after_valid_preflight(self):
        opener,calls=self.mock_opener([self.preflight,b'<html>Site Unavailable</html>'])
        with patch.object(cli,'build_opener',return_value=opener),self.assertRaises(ValueError):cli.download()
        self.assertEqual(len(calls),2)
    def test_network_redirect_and_cli_no_leak(self):
        with self.assertRaises(ValueError):cli._NoRedirect().redirect_request(None,None,302,'',{},cli.SOURCE)
        with patch.object(cli,'build_opener',side_effect=OSError('private-marker')),self.assertRaises(ValueError):cli.download()
        r=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/CATNET_VPN/server_catalog_decoder.py'),'--stdin'],
            input=b'<html>private-marker</html>',capture_output=True)
        self.assertEqual(r.returncode,1);self.assertEqual(r.stdout,b'');self.assertNotIn(b'private-marker',r.stderr)
if __name__=='__main__':unittest.main()
