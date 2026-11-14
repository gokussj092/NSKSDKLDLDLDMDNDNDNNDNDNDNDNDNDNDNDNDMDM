"""Tx build-70 source-derived fixtures and real worker contract."""
import base64
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from decoders.Python.apps.Tx_Tunnel import codec,file_decoder,server_catalog_decoder
from decoders.Python import ultra

ROOT=Path(__file__).resolve().parents[1]
VECTORS=json.loads((ROOT/'tests/golden/tx_tunnel_vectors.json').read_text())

class TxTunnelTests(unittest.TestCase):
    def test_four_independent_full_documents(self):
        for v in VECTORS['documents']:
            with self.subTest(kind=v['kind'],mode=v['mode']):
                actual=json.loads((file_decoder.run if v['kind']=='file' else server_catalog_decoder.run)(v['wire'].encode()))
                expected={'application':'TX TUNNEL','extension':'.tx','config':v['expected']} if v['kind']=='file' else v['expected']
                self.assertEqual(actual,expected)

    def test_outer_salt_nonce_and_tag_require_authentication(self):
        raw=base64.b64decode(VECTORS['documents'][0]['wire'])
        for offset in [0,16,28,len(raw)-1]:
            broken=bytearray(raw);broken[offset]^=1
            with self.subTest(offset=offset),self.assertRaises(ValueError):
                codec.open_document(base64.b64encode(broken))

    def test_inner_tag_failure_never_enters_permissive_historical_reader(self):
        outer=copy.deepcopy(VECTORS['documents'][0]['outer'])
        raw=bytearray(base64.b64decode(outer['Payload']));raw[-1]^=1;outer['Payload']=base64.b64encode(raw).decode()
        with patch.object(ultra,'decrypt_ultra_file',side_effect=AssertionError('legacy fallback must not run')):
            with self.assertRaises(ValueError):file_decoder.run(json.dumps(outer).encode())

    def test_authenticated_duplicate_json_never_enters_historical_reader(self):
        with patch.object(ultra,'decrypt_ultra_file',side_effect=AssertionError('legacy fallback must not run')):
            with self.assertRaises(ValueError):file_decoder.run(VECTORS['duplicate'].encode())

    def test_historical_both_aad_modes_and_untouched_siblings(self):
        from tests.test_ultra_sandok import config_fixture
        for aad in [True,False]:
            wire=config_fixture('txtunnel',aad=aad,inner=True)
            expected={'application':ultra.ULTRA_NAMES['.tx'],'extension':'.tx','config':ultra.decrypt_ultra_file(wire,'.tx')}
            self.assertEqual(json.loads(file_decoder.run(wire)),expected)
            self.assertEqual(json.loads(ultra.run(wire,'.tx')),expected)
        self.assertEqual(ultra.EXT_TO_KEY['.mmt'],'mmtunnel')

    def test_invalid_input_json_shape_numbers_and_limits(self):
        bad=[b'',b'\xff',b'AAAA',b'{}',b'[]',b'<html>error</html>',b'x'*(codec.MAX_BYTES+1),
             b'{"Name":"a","TunnelType":"SSH","x":NaN}',b'{"Name":"a","TunnelType":"SSH","x":1e9999}',
             b'{"Name":"a","TunnelType":"SSH","x":"\\ud800"}',b'{"Name":"a","TunnelType":false}']
        for wire in bad:
            with self.subTest(prefix=wire[:24]),self.assertRaises(ValueError):file_decoder.run(wire)
        for wire in [None,'x',bytearray(b'AAAA')]:
            with self.assertRaises(ValueError):file_decoder.run(wire)
        with self.assertRaises(ValueError):server_catalog_decoder.run(VECTORS['documents'][0]['wire'].encode())

    def test_worker_documents_registry_and_public_credentials(self):
        from cloud.workers.python.engine import decode_file,decode_provider_catalog,load_file_engines,load_runtime_file_engines
        base=load_file_engines();runtime=load_runtime_file_engines()
        self.assertEqual(len(base),240);self.assertEqual(len(runtime),270)
        self.assertIn('/apps/Tx_Tunnel/',runtime['tx']['source'])
        self.assertEqual(runtime['mm'],base['mm'])
        for v in VECTORS['documents']:
            r=decode_file('tx',v['wire'].encode()) if v['kind']=='file' else decode_provider_catalog('tx-tunnel',v['wire'].encode())
            expected={'application':'TX TUNNEL','extension':'.tx','config':v['expected']} if v['kind']=='file' else v['expected']
            self.assertEqual(r['structuredJson'],expected);self.assertEqual(json.loads(r['rawText']),expected);self.assertFalse(r['isPartial'])
        public=json.loads((ROOT/'cloud/web/content/file-formats.json').read_text())
        route=next(v for v in public['formats'] if v['suffix']=='tx')
        self.assertEqual(route['credentialFields'],[]);self.assertEqual(route['name'],'Tx Tunnel v2.17')

    def test_cli_stdin_and_sanitized_failure(self):
        path=ROOT/'decoders/Python/apps/Tx_Tunnel/file_decoder.py';v=VECTORS['documents'][0]
        r=subprocess.run([sys.executable,str(path),'-'],input=v['wire'].encode(),capture_output=True,timeout=20)
        self.assertEqual(r.returncode,0);self.assertEqual(json.loads(r.stdout)['config'],v['expected'])
        r=subprocess.run([sys.executable,str(path),'-'],input=b'synthetic-private-corrupt',capture_output=True,timeout=20)
        self.assertNotEqual(r.returncode,0);self.assertEqual(r.stdout,b'');self.assertNotIn(b'synthetic-private-corrupt',r.stderr)

    def test_fixed_get_uses_exact_apk_size_code_and_resource_agent(self):
        class Response:
            status=200;headers={}
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,n):return b'synthetic'
        with patch.object(server_catalog_decoder,'build_opener') as b:
            b.return_value.open.return_value=Response();self.assertEqual(server_catalog_decoder.download(),b'synthetic')
            req=b.return_value.open.call_args.args[0]
            self.assertEqual(req.full_url,'https://strongteam.co/api/txtunnel/v1/?appcode=27.0')
            self.assertEqual(req.get_method(),'GET');self.assertIsNone(req.data);self.assertEqual(req.get_header('User-agent'),'Tx Tunnel')
        self.assertEqual(str(float(f'{28308691/1048576:.2f}')),'27.0')
        with self.assertRaises(ValueError):server_catalog_decoder._NoRedirect().redirect_request(None,None,302,'',{},'https://bad.invalid/')

if __name__=='__main__':unittest.main()
