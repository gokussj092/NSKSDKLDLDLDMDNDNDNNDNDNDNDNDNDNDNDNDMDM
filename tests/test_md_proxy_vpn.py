"""MD29 reuses the statically checked primitive, keeps one complete document."""
import base64,json,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from decoders.Python.apps.MD_Proxy_VPN import codec,server_catalog_decoder as cli
ROOT=Path(__file__).resolve().parents[1]
V=json.loads((ROOT/'tests/golden/ultra_tunnel_vectors.json').read_text())
class MDProxyTests(unittest.TestCase):
    def test_independent_jca_fixtures_plain_bundled_and_remote(self):
        for case in V['documents']:
            self.assertEqual(codec.decode_catalog(case['wire'].encode()),case['expected'])
    def test_actual_worker_returns_one_whole_document(self):
        from cloud.workers.python.engine import decode_provider_catalog
        case=V['documents'][2];r=decode_provider_catalog('md-proxy-vpn',case['wire'].encode())
        self.assertEqual(r['structuredJson'],case['expected']);self.assertEqual(json.loads(r['rawText']),case['expected']);self.assertFalse(r['isPartial'])
    def test_invalid_inner_tag_rejects_all_results(self):
        doc=json.loads(V['documents'][0]['wire']);raw=bytearray(base64.b64decode(doc['Networks'][0]['Payload']));raw[-1]^=1;doc['Networks'][0]['Payload']=base64.b64encode(raw).decode()
        with self.assertRaises(ValueError):codec.decode_catalog(json.dumps(doc).encode())
    def test_html_empty_bad_schema_and_corrupt_outer_are_rejected(self):
        for raw in [b'',b'<html>private-marker</html>',b'{"Version":"1","Servers":[],"Networks":[]}',V['documents'][2]['wire'][:-1].encode()]:
            with self.assertRaises(ValueError) as e:codec.decode_catalog(raw)
            self.assertNotIn('private-marker',str(e.exception))
    def test_cli_stdin_and_file_work_outside_checkout(self):
        script=ROOT/'decoders/Python/apps/MD_Proxy_VPN/server_catalog_decoder.py';case=V['documents'][2]
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'catalog.bin';path.write_text(case['wire'])
            for args in [[str(path)],['--stdin']]:
                r=subprocess.run([sys.executable,str(script),*args],input=case['wire'].encode(),capture_output=True,cwd=d,timeout=20)
                self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(json.loads(r.stdout),case['expected'])
    def test_download_pins_uppercase_native_agent_and_refuses_redirects(self):
        class Reply:
            status=200;headers={}
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def read(self,n):return V['documents'][2]['wire'].encode()[:n]
        with patch.object(cli,'build_opener') as p:
            p.return_value.open.return_value=Reply();cli.download();req=p.return_value.open.call_args.args[0]
            self.assertEqual(req.full_url,'https://strongteam.co/api/ultrasystem/ultrav3.txt');self.assertEqual(req.get_header('User-agent'),'MD PROXY VPN')
        with self.assertRaises(ValueError):cli._NoRedirect().redirect_request(None)
if __name__=='__main__':unittest.main()
