"""CREEB VPN 50.0: full independent JDK vectors, routing and rejection cases."""
from __future__ import annotations
import base64
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from decoders.Python.apps.CREEB_VPN import codec,file_decoder,server_catalog_decoder

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'cloud/workers/python'))
FIXTURE=json.loads((ROOT/'tests/golden/creeb_vpn_vectors.json').read_text())


class CreebVpnTests(unittest.TestCase):
    def test_all_jdk_documents_and_direct_json_match_in_full(self):
        for v in FIXTURE['documents']:
            with self.subTest(name=v['name']):
                for data in (v['cipher'].encode(),json.dumps(v['outer'],ensure_ascii=False).encode()):
                    self.assertEqual(codec.decode(data),v['expected'])
                    self.assertEqual(json.loads(file_decoder.run(data)),v['expected'])

    def test_two_keys_little_endian_length_boundaries_unicode_and_empty(self):
        for v in FIXTURE['primitives']:
            key=codec.OUTER_KEY if v['key']=='C' else codec.SERVER_KEY
            self.assertEqual(codec.decrypt_text(v['cipher'],key).encode(),base64.b64decode(v['plainBase64']))
        self.assertEqual(codec.decrypt_text('',codec.SERVER_KEY),'')
        self.assertEqual(len(codec.SERVER_KEY),21) # Truncate UTF-8 bytes, not Unicode characters.

    def test_custom_and_bundled_tweaks_use_pinfo_without_key_guessing(self):
        v=next(v for v in FIXTURE['documents'] if v['name']=='mixed-keys')
        self.assertEqual(codec.decode(v['cipher'].encode()),v['expected'])
        outer=copy.deepcopy(v['outer']);outer['Tweaks'][0]['pInfo']='custom tweak'
        with self.assertRaises(ValueError):codec.decode(json.dumps(outer).encode())
        outer=copy.deepcopy(v['outer']);outer['Servers'][0]['ServerIP']=outer['Tweaks'][0]['Payload']
        with self.assertRaises(ValueError):codec.decode(json.dumps(outer).encode())

    def test_security_is_metadata_no_external_password_hwid_or_time(self):
        v=next(v for v in FIXTURE['documents'] if v['name']=='locked')
        actual=codec.decode(v['cipher'].encode())
        self.assertEqual(actual['Security'],v['expected']['Security'])
        self.assertEqual(actual['Security']['Password'],'synthetic password')
        self.assertEqual(actual['Security']['ExpiryDate'],1)
        self.assertEqual(actual['Servers'][0]['extra'],v['expected']['Servers'][0]['extra'])

    def test_catalog_is_complete_and_rejects_file_only_and_html(self):
        v=next(v for v in FIXTURE['documents'] if v['name']=='catalog')
        self.assertEqual(json.loads(server_catalog_decoder.run(v['cipher'].encode())),v['expected'])
        for data in (FIXTURE['documents'][0]['cipher'].encode(),b'<html>Site Unavailable</html>'):
            with self.assertRaises(ValueError):server_catalog_decoder.run(data)

    def test_malformed_base64_framing_utf8_json_and_limits_fail_closed(self):
        for data in (b'',b'x'*(codec.MAX_BYTES+1),b'AAAA',b'@@@@@@@@',b'crev://AAAA',b'\xff',
                     b'{"Servers":[1]}',b'{"Servers":[]}',b'{"Servers":"x"}',b'{"Servers":[{}],"Security":[]}',
                     b'{"Servers":[{}],"x":NaN}',b'{"Servers":[{}],"x":1e9999}',b'{"Servers":[{}],"x":"\\ud800"}',
                     b'{"Servers":[{}],"Servers":[{}]}'):
            with self.subTest(kind=data[:30]):
                with self.assertRaises(ValueError):codec.decode(data)
        for value in (None,'x',bytearray(b'AAAA')):
            with self.assertRaises(ValueError):codec.decode(value)
        for text in ('notbase64',base64.b64encode(bytes(12)).decode()):
            with self.assertRaises(ValueError):codec.decrypt_text(text,codec.OUTER_KEY)
        # A broken inner field must not return the partially decrypted JSON.
        broken=copy.deepcopy(FIXTURE['documents'][0]['outer']);broken['Servers'][0]['ServerPass']='corrupt'
        with self.assertRaises(ValueError):codec.decode(json.dumps(broken).encode())

    def test_cli_outside_checkout_path_and_stdin(self):
        with tempfile.TemporaryDirectory() as folder:
            v=FIXTURE['documents'][1];data=v['cipher'].encode();p=Path(folder)/'sample.crev';p.write_bytes(data)
            for args,incoming in (([str(p)],None),(['-'],data)):
                proc=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/CREEB_VPN/file_decoder.py'),*args],
                                    input=incoming,cwd=folder,capture_output=True,timeout=20)
                self.assertEqual(proc.returncode,0);self.assertEqual(proc.stderr,b'')
                self.assertEqual(json.loads(proc.stdout),v['expected'])

    def test_worker_and_http_preserve_full_file_and_catalog(self):
        from cloud.workers.python import engine,server
        for name in ('locked','catalog'):
            v=next(v for v in FIXTURE['documents'] if v['name']==name);data=v['cipher'].encode()
            result=engine.decode_provider_catalog('creeb-vpn',data) if name=='catalog' else engine.decode_file('crev',data)
            self.assertEqual(result['structuredJson'],v['expected']);self.assertFalse(result['isPartial'])
            self.assertEqual(json.loads(result['rawText']),v['expected'])
        v=FIXTURE['documents'][1]
        body=json.dumps({'format':'crev','dataBase64':base64.b64encode(v['cipher'].encode()).decode()}).encode()
        replies=[];fake=SimpleNamespace(path='/internal/v1/decode/file',headers={'Content-Length':str(len(body))},
            rfile=io.BytesIO(body),_authorized=lambda:True,_json=lambda code,value:replies.append((code,value)))
        server.WorkerHandler.do_POST(fake)
        self.assertEqual(replies[0][0],200);self.assertEqual(replies[0][1]['structuredJson'],v['expected'])
        v=next(v for v in FIXTURE['documents'] if v['name']=='catalog')
        body=json.dumps({'providerId':'creeb-vpn','dataBase64':base64.b64encode(v['cipher'].encode()).decode()}).encode()
        replies.clear();fake.path='/internal/v1/decode/import/server-vpn'
        fake.headers={'Content-Length':str(len(body))};fake.rfile=io.BytesIO(body)
        server.WorkerHandler.do_POST(fake)
        self.assertEqual(replies[0][0],200);self.assertEqual(replies[0][1]['structuredJson'],v['expected'])

    def test_bot_routes_and_legacy_aliases_remain_distinct(self):
        from spdecode.registry import get_decoder,get_supported_extension
        self.assertEqual(get_supported_extension('Example.CREV'),'crev')
        self.assertTrue(get_decoder('crev').script.endswith('/CREEB_VPN/file_decoder.py'))
        self.assertTrue(get_decoder('creeb').script.endswith('/CREEB_INJECTOR/file_decoder.py'))
        for suffix in ('cer','cerv'):self.assertEqual(get_decoder(suffix).script,'decoders/Python/crev.py')


if __name__=='__main__':unittest.main()
