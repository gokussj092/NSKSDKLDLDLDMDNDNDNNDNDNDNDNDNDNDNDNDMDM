"""MM builds 45/47: original hash POST, complete JSON and worker parity."""
import base64
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from decoders.Python.apps.MM_Tunnel import codec, file_decoder, server_catalog_decoder

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = json.loads((ROOT/"tests/golden/mm_tunnel_vectors.json").read_text())


class MMTunnelTests(unittest.TestCase):
    def test_three_profile_forms_match_independent_full_json(self):
        for case in GOLDEN["documents"]:
            if case["kind"] != "file":
                continue
            with self.subTest(mode=case["mode"]):
                wire=case["wire"].encode()
                self.assertEqual(codec.decode_file(wire),case["expected"])
                self.assertEqual(json.loads(file_decoder.run(wire)),{
                    "application":"MM Tunnel","extension":".mmt","config":case["expected"]})

    def test_three_catalog_forms_preserve_every_field_and_type(self):
        for case in GOLDEN["documents"]:
            if case["kind"] == "catalog":
                with self.subTest(mode=case["mode"]):
                    self.assertEqual(json.loads(server_catalog_decoder.run(case["wire"].encode())),case["expected"])
        with self.assertRaises(ValueError):
            server_catalog_decoder.run(GOLDEN["documents"][0]["wire"].encode())

    def test_kdf_matches_libsodium_independent_vector(self):
        from argon2.low_level import Type, hash_secret_raw
        v=GOLDEN["kdf"]
        self.assertEqual(hash_secret_raw(v["password"].encode(),bytes.fromhex(v["saltHex"]),3,16384,1,32,Type.ID).hex(),v["keyHex"])

    def test_authentication_failure_in_outer_salt_nonce_tag_and_inner(self):
        v=GOLDEN["documents"][0]
        text=v["wire"];raw=base64.b64decode(text[:3]+text[4:])
        for index in (0,16,28,len(raw)-1):
            broken=bytearray(raw);broken[index]^=1
            b=base64.b64encode(broken).decode();b=b[:3]+"A"+b[3:]
            with self.subTest(index=index),self.assertRaises(ValueError):
                codec.decode_file(b.encode())
        outer=copy.deepcopy(v["outer"])
        inner=bytearray(base64.b64decode(outer["Payload"]));inner[-1]^=1
        outer["Payload"]=base64.b64encode(inner).decode()
        with self.assertRaises(ValueError):
            file_decoder.run(json.dumps(outer).encode())

    def test_invalid_size_shape_utf8_json_duplicates_and_nonfinite(self):
        bad=(b'',b'\xff',b'AAAA',b'<html>Forbidden</html>',b'{}',b'[]',b'mmt://AAAA',
             b'{"Name":"a","TunnelType":1}',b'{"Name":"a","TunnelType":"x","Name":"b"}',
             b'{"Name":"a","TunnelType":"x","n":NaN}',b'{"Name":"a","TunnelType":"x","n":1e999}',
             b'{"Name":"a","TunnelType":"x","s":"\\ud800"}',b'x'*(codec.MAX_BYTES+1))
        for wire in bad:
            with self.subTest(prefix=wire[:24]),self.assertRaises(ValueError):
                codec.decode_file(wire)
        for wire in (None,'abc',bytearray(b'AAAA')):
            with self.assertRaises(ValueError):codec.decode_file(wire)

    def test_plaintext_empty_unknown_and_json_string_values_are_preserved(self):
        profile={"Name":"synthetic","TunnelType":"SSH","Payload":"","URI":None,
                 "Extra":'{"keep":"string"}',"security":{"password":"synthetic","HWID":"test"}}
        self.assertEqual(codec.decode_file(json.dumps(profile).encode()),profile)
        profile["Payload"]="plain.example.invalid"
        self.assertEqual(codec.decode_file(json.dumps(profile).encode()),profile)

    def test_metadata_and_unknown_field_contexts_never_enter_the_kdf(self):
        profile={"Name":"synthetic","TunnelType":"SSH","Info":"A"*64,"URI":False,
                 "future":{"Payload":"A"*64,"ServerIPHost":"B"*64}}
        self.assertEqual(codec.decode_file(json.dumps(profile).encode()),profile)
        catalog={"Version":"synthetic","Servers":[{"Name":"s","Payload":"A"*64}],
                 "Networks":[profile],"future":{"OVPNPass":"B"*64}}
        self.assertEqual(codec.decode_catalog(json.dumps(catalog).encode()),catalog)

    def test_historical_mmt_both_aad_variants_and_other_suffixes_unchanged(self):
        from decoders.Python import ultra
        from tests.test_ultra_sandok import config_fixture
        for aad in (True,False):
            wire=config_fixture("mmtunnel",aad=aad,inner=True)
            expected={"application":ultra.ULTRA_NAMES['.mmt'],"extension":".mmt",
                      "config":ultra.decrypt_ultra_file(wire,'.mmt')}
            self.assertEqual(json.loads(file_decoder.run(wire)),expected)
            self.assertEqual(json.loads(ultra.run(wire,'.mmt')),expected)
        self.assertEqual(ultra.EXT_TO_KEY['.mm'],'mmtunnel')

    def test_real_worker_file_and_catalog_complete_json_and_registry(self):
        from cloud.workers.python.engine import decode_file,decode_provider_catalog,load_file_engines,load_runtime_file_engines
        canonical=load_file_engines();runtime=load_runtime_file_engines()
        self.assertEqual(len(canonical),240);self.assertEqual(len(runtime),270)
        self.assertIn('/apps/MM_Tunnel/',runtime['mmt']['source'])
        self.assertEqual(runtime['mm'],canonical['mm'])
        self.assertEqual(runtime['md'],canonical['md'])
        for case in GOLDEN['documents']:
            if case['mode']=='plain':continue
            wire=case['wire'].encode()
            result=(decode_file('mmt',wire) if case['kind']=='file' else decode_provider_catalog('mm-tunnel',wire))
            expected=case['expected']
            if case['kind']=='file':expected={"application":"MM Tunnel","extension":".mmt","config":expected}
            self.assertEqual(result['structuredJson'],expected)
            self.assertEqual(json.loads(result['rawText']),expected)
            self.assertFalse(result['isPartial'])

    def test_cli_stdin_matches_and_failure_never_exposes_values(self):
        case=GOLDEN['documents'][0]
        path=ROOT/'decoders/Python/apps/MM_Tunnel/file_decoder.py'
        result=subprocess.run([sys.executable,str(path),'-'],input=case['wire'].encode(),capture_output=True,timeout=20)
        self.assertEqual(result.returncode,0)
        self.assertEqual(json.loads(result.stdout)['config'],case['expected'])
        result=subprocess.run([sys.executable,str(path),'-'],input=b'private-corrupt-data',capture_output=True,timeout=20)
        self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')
        self.assertNotIn(b'private-corrupt-data',result.stderr)

    def test_downloader_is_fixed_post_and_redirects_rejected(self):
        class Response:
            status=200
            headers={}
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,n):return b'synthetic response'
        with patch.object(server_catalog_decoder,'build_opener') as builder:
            builder.return_value.open.return_value=Response()
            self.assertEqual(server_catalog_decoder.download(),b'synthetic response')
            request=builder.return_value.open.call_args.args[0]
            self.assertEqual(request.full_url,'https://strongteam.co/api/mmtunnel/')
            self.assertEqual(request.get_method(),'POST')
            self.assertEqual(request.data,b'hash=xsandokUpdatex')
            self.assertEqual(request.get_header('Content-type'),'application/x-www-form-urlencoded')
            self.assertEqual(request.get_header('User-agent'),'Go-http-client/1.1')
        with self.assertRaises(ValueError):server_catalog_decoder._NoRedirect().redirect_request(None,None,302,'',{},'https://bad.invalid/')


if __name__=='__main__':unittest.main()
