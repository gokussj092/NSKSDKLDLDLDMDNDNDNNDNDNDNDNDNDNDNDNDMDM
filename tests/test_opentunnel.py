"""OpenTunnel61 complete properties, independent JCA vectors and SSH host list."""
import base64,hashlib,importlib.util,json,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from decoders.Python.apps.OpenTunnel import file_codec as codec,server_catalog_decoder as catalog
ROOT=Path(__file__).resolve().parents[1];DOS=ROOT/'analysis/com.opentunnel.app/61'
V=json.loads((DOS/'tests/fixtures/vectors.json').read_text())
HOSTS={'status':200,'count':1,'servers':[{'hostname':'ssh.example.invalid','premium':False,'status':True,'future':[None,0,'ñ']}]}

class OpenTunnelTests(unittest.TestCase):
    def test_all_three_independent_java_framings_keep_every_property(self):
        for case in V['documents']:
            with self.subTest(mode=case['mode']):self.assertEqual(codec.decode_file(base64.b64decode(case['base64'])),V['expected'])
        self.assertEqual(V['expected']['sshPass'],'');self.assertEqual(V['expected']['sshCredsRedacted'],'1')
    def test_java_oracle_is_reproducible(self):
        spec=importlib.util.spec_from_file_location('open_vectors',DOS/'tools/vectors.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        self.assertEqual(m.generate(),V)
    def test_large_multiline_property_is_complete(self):
        spec=importlib.util.spec_from_file_location('open_vectors',DOS/'tools/vectors.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        expected={**V['expected'],'proxyPayload':'\r\n'.join('línea '+str(i) for i in range(5000))}
        fixture=m.generate(expected);case=fixture['documents'][1]
        from cloud.workers.python.engine import decode_file
        result=decode_file('tnl',base64.b64decode(case['base64']))
        self.assertEqual(result['structuredJson'],expected);self.assertEqual(json.loads(result['rawText']),expected);self.assertFalse(result['isPartial'])
    def test_crc_tag_length_and_trailing_bytes_fail(self):
        for case in V['documents']:
            raw=base64.b64decode(case['base64'])
            for corrupt in [raw[:-1],raw+b'!',b'OPL\x02',b'<html>private-marker</html>',b'']:
                with self.subTest(mode=case['mode'],size=len(corrupt)),self.assertRaises(ValueError) as e:codec.decode_file(corrupt)
                self.assertNotIn('private-marker',str(e.exception))
        raw=bytearray(base64.b64decode(V['documents'][0]['base64']));raw[-2]=ord('A') if raw[-2]!=ord('A') else ord('B')
        with self.assertRaises(ValueError):codec.decode_file(bytes(raw))
    def test_xml_entities_duplicates_and_wrong_mode_fail(self):
        for raw in [b'<!DOCTYPE properties [<!ENTITY a "x">]><properties/>',b'<properties><entry key="CONFIG_MODE">3</entry><entry key="x">a</entry><entry key="x">b</entry></properties>',b'<properties><entry key="CONFIG_MODE">999</entry></properties>',b'<properties><entry key="CONFIG_MODE"><nested/></entry></properties>']:
            with self.assertRaises(ValueError):codec.properties(raw)
    def test_historical_c0_gcm_is_still_readable(self):
        from tests.golden.a23_batch5 import tnl_bytes
        self.assertEqual(codec.decode_file(tnl_bytes()),{'Host':'example.org','Port':'443'})
    def test_worker_inventory_is_frozen_and_overlay_is_explicit(self):
        from cloud.workers.python.engine import load_file_engines,load_runtime_file_engines,decode_file
        self.assertEqual(len(load_file_engines()),240);self.assertEqual(len(load_runtime_file_engines()),270)
        self.assertIn('/OpenTunnel/file_decoder.py',load_runtime_file_engines()['tnl']['source'])
        for case in V['documents']:
            result=decode_file('tnl',base64.b64decode(case['base64']));self.assertEqual(result['structuredJson'],V['expected'])
    def test_public_ssh_list_is_preserved_without_creating_credentials(self):
        from cloud.workers.python.engine import decode_provider_catalog
        raw=json.dumps(HOSTS).encode();self.assertEqual(catalog.decode_catalog(raw),HOSTS)
        r=decode_provider_catalog('opentunnel-ssh',raw);self.assertEqual(r['structuredJson'],HOSTS);self.assertFalse(r['isPartial']);self.assertTrue(r['warnings'])
        self.assertNotIn('username',r['structuredJson']['servers'][0])
    def test_ssh_schema_html_duplicates_and_mismatched_count_fail(self):
        for data in [b'<html/>',b'{"status":200,"count":0,"count":1,"servers":[]}',json.dumps({**HOSTS,'count':2}).encode(),json.dumps({**HOSTS,'status':True}).encode(),json.dumps({**HOSTS,'servers':[{'hostname':None}]}).encode()]:
            with self.assertRaises(ValueError):catalog.decode_catalog(data)
    def test_cli_works_outside_checkout_and_download_cannot_redirect(self):
        with tempfile.TemporaryDirectory() as d:
            for path,raw,args in [(ROOT/'decoders/Python/apps/OpenTunnel/file_decoder.py',base64.b64decode(V['documents'][1]['base64']),['--stdin']),(ROOT/'decoders/Python/apps/OpenTunnel/server_catalog_decoder.py',json.dumps(HOSTS).encode(),['--stdin'])]:
                p=subprocess.run([sys.executable,str(path),*args],input=raw,cwd=d,capture_output=True,timeout=15)
                self.assertEqual(p.returncode,0,p.stderr);self.assertIsInstance(json.loads(p.stdout),dict)
        with self.assertRaises(ValueError):catalog._NoRedirect().redirect_request(None)
    def test_original_icon_and_input_bound(self):
        a=(ROOT/'cloud/web/public/server-vpn-icons/opentunnel.png').read_bytes();b=(ROOT/'decoders/Python/apps/OpenTunnel/OpenTunnel.png').read_bytes()
        self.assertEqual(a,b);self.assertEqual(hashlib.sha256(a).hexdigest(),'2687863c67e82e2fcff500ffd34d4fff6ec5b59662a4db6eb96650ed6aca8c98')
        with patch.object(codec,'MAX_INPUT',4),self.assertRaises(ValueError):codec.decode_file(b'12345')
if __name__=='__main__':unittest.main()
