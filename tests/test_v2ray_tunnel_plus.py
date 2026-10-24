"""Full subscriptions, independent Java wire parity and isolated Cloud flow."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from decoders.Python.apps.V2ray_Tunnel_Plus import codec,server_catalog_decoder as catalog
ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'decoders/Python/apps/V2ray_Tunnel_Plus'
V=json.loads((ROOT/'tests/golden/v2ray_tunnel_plus_vectors.json').read_text())

class V2rayTunnelPlusTests(unittest.TestCase):
    def test_complete_plain_and_base64_documents_preserve_every_uri_and_field(self):
        with patch.object(catalog,'download',side_effect=AssertionError('network')):
            self.assertEqual(json.loads(catalog.run(V['raw'].encode())),V['expectedRaw'])
            self.assertEqual(json.loads(catalog.run(V['base64'].encode())),V['expectedBase64'])
        p=V['expectedRaw']['profiles'];self.assertEqual(len(p),12)
        self.assertEqual(p[0]['query'][-4:],[['x','first'],['x','second'],['blank',''],['flag','']])
        self.assertEqual(p[1]['config']['unknown'],{'nested':[None,False,12]})
        self.assertIsInstance(p[1]['config']['port'],int)
        self.assertEqual(p[3]['host'],'2001:db8::1');self.assertEqual(p[4]['credentials']['password'],'pa:ss')

    def test_complete_pair_keeps_both_sources_and_rejects_swaps_omissions_and_duplicates(self):
        data=catalog.pack_catalogs(V['base64'].encode(),V['raw'].encode())
        expected={'provider':'v2ray-tunnel-plus','complete':True,'catalogs':{'base64':V['expectedBase64'],'raw':V['expectedRaw']}}
        self.assertEqual(json.loads(catalog.run(data)),expected)
        obj=json.loads(data);bad=[]
        for name in ['base64','raw']:
            x=json.loads(data);del x['catalogs'][name];bad.append(json.dumps(x).encode())
            x=json.loads(data);x['catalogs'][name]='!';bad.append(json.dumps(x).encode())
        x=json.loads(data);x['catalogs']['raw']=obj['catalogs']['base64'];bad.append(json.dumps(x).encode())
        bad += [b'{"kind":"x","kind":"y","catalogs":{}}']
        for item in bad:
            with self.assertRaises(codec.DecodeError):catalog.run(item)
        with self.assertRaises(codec.DecodeError):catalog.pack_catalogs(b'',b'x')
        with self.assertRaises(codec.DecodeError):catalog.pack_catalogs(b'x'*(4*1024*1024),b'x'*(4*1024*1024))

    def test_no_truncation_deduplication_or_first_record_only_behavior(self):
        lines=V['raw'].strip().splitlines();line=next(s for s in lines if s.strip())
        text='\n'.join([line]*1000)+'\n';result=codec.decode_catalog(text.encode())
        self.assertEqual(result['count'],1000);self.assertEqual(len(result['profiles']),1000)
        self.assertEqual(result['profiles'][-1]['line'],1000);self.assertEqual(result['text'],text)

    def test_invalid_later_record_fails_without_partial_json_or_private_error_details(self):
        for data in [V['raw']+'\nbogus://private-invalid-input',V['raw']+'\nvless://user@host.invalid:999999',
            'vmess://'+base64.b64encode(b'{"add":"a","add":"b"}').decode(),
            'vmess://'+base64.b64encode(b'{"add":"a","port":443,"id":"x","net":"tcp","x":NaN}').decode(),
            'ss://'+base64.b64encode(b'no-credentials').decode(), 'vless://user@example.invalid:443?x=%ZZ', '!!!!']:
            with self.assertRaises(codec.DecodeError) as e:catalog.run(data.encode())
            self.assertNotIn('private-invalid-input',str(e.exception))
        obj={'add':'a','port':443,'id':'x','net':'tcp','x':[]}
        for _ in range(65):obj['x']=[obj['x']]
        with self.assertRaises(codec.DecodeError):catalog.run(('vmess://'+base64.b64encode(json.dumps(obj).encode()).decode()).encode())

    def test_input_output_limits_and_malformed_scheme_are_explicit_errors(self):
        for raw in [b'',b'x'*(codec.MAX_BYTES+1),b'\xff\xff']:
            with self.assertRaises(codec.DecodeError):catalog.run(raw)
        with self.assertRaises(codec.DecodeError):codec.render({'x':'x'*codec.MAX_BYTES})
        for raw in ['vless://@example.invalid:443','vless://user@example.invalid','vless://u@example.invalid:0','https://example.invalid/list']:
            with self.assertRaises(codec.DecodeError):catalog.run(raw.encode())

    def test_both_isolated_sources_and_pair_match_complete_expected_json(self):
        sys.path.insert(0,str(ROOT/'cloud/workers/python'))
        from engine import decode_provider_catalog
        data=catalog.pack_catalogs(V['base64'].encode(),V['raw'].encode());result=decode_provider_catalog('v2ray-tunnel-plus',data)
        expected={'provider':'v2ray-tunnel-plus','complete':True,'catalogs':{'base64':V['expectedBase64'],'raw':V['expectedRaw']}}
        self.assertEqual(result['structuredJson'],expected);self.assertFalse(result['isPartial'])
        self.assertEqual(json.loads(result['rawText']),expected)

    def test_cli_file_and_stdin_work_outside_repository_without_network(self):
        env={k:v for k,v in os.environ.items() if k!='PYTHONPATH'}
        with tempfile.TemporaryDirectory() as folder:
            for key,expected in [('base64','expectedBase64'),('raw','expectedRaw')]:
                source=Path(folder)/'copy.txt';source.write_text(V[key])
                for flags in [[str(source)],['--stdin']]:
                    p=subprocess.run([sys.executable,str(APP/'server_catalog_decoder.py'),*flags],input=V[key].encode(),capture_output=True,cwd=folder,env=env,timeout=10)
                    self.assertEqual(p.returncode,0,p.stderr.decode());self.assertEqual(json.loads(p.stdout),V[expected])
            p=subprocess.run([sys.executable,str(APP/'server_catalog_decoder.py'),'--stdin'],input=b'private-invalid-input',capture_output=True,cwd=folder,env=env,timeout=10)
            self.assertNotEqual(p.returncode,0);self.assertFalse(p.stdout);self.assertNotIn(b'private-invalid-input',p.stderr)

    def test_cli_defaults_to_both_complete_sources_and_can_select_each_feed(self):
        for flags,expected in [([],[False,True]),(['--all'],[False,True]),(['--raw'],[True]),(['--base64'],[False])]:
            seen=[]
            def download(*,raw=False):seen.append(raw);return V['raw' if raw else 'base64'].encode()
            with patch.object(catalog,'download',side_effect=download),patch.object(sys,'argv',['catalog',*flags]),patch('sys.stdout'):
                self.assertEqual(catalog.main(),0)
            self.assertEqual(seen,expected)

    def test_fixed_source_downloads_reject_redirects_html_empty_and_compression(self):
        class Response:
            status=200;headers={};data=V['raw'].encode()
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,size):return self.data[:size]
        with patch.object(catalog,'build_opener') as op:
            op.return_value.open.return_value=Response()
            for raw,url in [(False,catalog.BASE64_URL),(True,catalog.RAW_URL)]:
                self.assertEqual(catalog.download(raw=raw),Response.data)
                self.assertEqual(op.return_value.open.call_args.args[0].full_url,url)
            for data in [b'',b'<html/>',b'x'*(codec.MAX_BYTES+1)]:
                with patch.object(Response,'data',data),self.assertRaises(codec.DecodeError):catalog.download()
            with patch.object(Response,'status',404),self.assertRaises(codec.DecodeError):catalog.download()
            with patch.object(Response,'headers',{'Content-Encoding':'gzip'}),self.assertRaises(codec.DecodeError):catalog.download()
        with self.assertRaises(codec.DecodeError):catalog._NoRedirect().redirect_request(None,None,302,'',{},'https://example.invalid')

    @unittest.skipUnless(shutil.which('java'),'JDK unavailable')
    def test_independent_jdk_oracle_reproduces_every_synthetic_uri_and_unwrap(self):
        profiles=V['expectedRaw']['profiles'];tasks=[('base64',V['base64'])]+[('uri',p['uri']) for p in profiles]
        raw=''.join(op+'\t'+base64.b64encode(text.encode()).decode()+'\n' for op,text in tasks)
        p=subprocess.run(['java',str(ROOT/'tests/golden/v2ray_tunnel_plus_oracle.java')],input=raw,text=True,capture_output=True,timeout=30)
        self.assertEqual(p.returncode,0,p.stderr);values=[base64.b64decode(v).decode() for v in p.stdout.splitlines()]
        self.assertEqual(values[0],V['raw']);self.assertEqual([json.loads(v) for v in values[1:]],[{k:v for k,v in p.items() if k!='line'} for p in profiles])

    def test_original_png_is_exact_and_identical_to_cloud_icon(self):
        icon=(APP/'V2ray_Tunnel_Plus.png').read_bytes()
        self.assertEqual(icon,(ROOT/'cloud/web/public/server-vpn-icons/v2ray-tunnel-plus.png').read_bytes())
        self.assertEqual(hashlib.sha256(icon).hexdigest(),'b87f9c792ec5271da31e255cf957e02abf8fbafd0f1f2737549f232d47cfb47f')

if __name__=='__main__':unittest.main()
