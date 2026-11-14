"""MTM full catalogs vs independent JDK; .v2 collision and standalone CLI."""
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from decoders.Python.apps.MTM_Tunnel_Lite import codec, file_decoder
from decoders.Python.apps.HX_Tunnel_VPN import HX_Tunnel_VPN as shared
from decoders.Python import EV2RAY
from scripts.apk_analysis.mtm_bundle import build
from tests.golden.a23_generators import ev2ray_profile

ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = {"Version":"synthetic", "Free_servers":[{"server_name":"ñ 中 😀", "password":"synthetic-only",
    "username":"user", "server_host":"example.invalid", "server_port":"443", "ssl_port":"443",
    "server_udp_port":"7300", "custom_cert":"cert\nline"}], "Premium_servers":[], "Vip_servers":[],
    "Private_servers":[], "Payloads":[{"host":"example.invalid", "sausage":"proxy.invalid", "port":"80",
    "payload":"GET / HTTP/1.1\r\nHost: test\r\n", "method":3, "sslws":True, "dothost":"dns.invalid"}],
    "Changelogs":"keep", "Username":"account", "Password":"account-secret", "unknown":{"keep":[False,None,0,""]}}


def oracle(pairs):
    incoming = ''.join(mode+'\t'+base64.b64encode(data).decode()+'\n' for mode,data in pairs)
    r = subprocess.run(['java',str(ROOT/'tests/golden/mtm_oracle.java')],input=incoming,text=True,
                       capture_output=True,timeout=30,check=True)
    return [base64.b64decode(line,validate=True) for line in r.stdout.splitlines()]


class MtmTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plain = json.dumps(DOCUMENT,ensure_ascii=False).encode()
        cls.cipher,cls.bad_schema,cls.duplicates = oracle([('seal',cls.plain),
            ('seal',b'{"Version":"1","Free_servers":[1],"Payloads":[]}'),
            ('seal',b'{"Version":"1","Free_servers":[],"Payloads":[],"Password":"a","Password":"b"}')])

    def test_whole_document_jdk_shared_primitive_and_both_adapters_match(self):
        self.assertEqual(oracle([('open',self.cipher)])[0],self.plain)
        self.assertEqual(codec.decode_bytes(self.cipher),self.plain)
        self.assertEqual(shared.decrypt_catalog_bytes(self.cipher,key=b'Princie!'),self.plain)
        self.assertEqual(codec.decode(self.cipher),DOCUMENT)
        self.assertEqual(json.loads(codec.run(self.cipher)),DOCUMENT)
        self.assertEqual(json.loads(file_decoder.run(self.cipher)),DOCUMENT)
        self.assertEqual(codec.decode(b'\xef\xbb\xbf\n'+self.cipher+b'\r\n'),DOCUMENT)

    def test_complete_worker_and_file_results(self):
        from cloud.workers.python.engine import decode_file,decode_provider_catalog
        for result in (decode_file('v2',self.cipher),decode_provider_catalog('mtm-tunnel-lite',self.cipher)):
            self.assertEqual(result['structuredJson'],DOCUMENT)
            self.assertEqual(json.loads(result['rawText']),DOCUMENT)
            self.assertFalse(result['isPartial'])

    def test_existing_v2ray_vectors_keep_exact_raw_outputs(self):
        from cloud.workers.python.engine import decode_file
        for encrypted in (False,True):
            data=ev2ray_profile(encrypted=encrypted)
            expected=EV2RAY.run(data)
            self.assertIsNotNone(expected)
            self.assertEqual(file_decoder.run(data),expected)
            self.assertEqual(decode_file('v2',data)['rawText'],expected+'\n')

    def test_malformed_catalog_never_falls_into_v2ray(self):
        with patch.object(EV2RAY,'run',side_effect=AssertionError('unexpected fallback')):
            self.assertIsNone(file_decoder.run(self.bad_schema))
            self.assertIsNone(file_decoder.run(self.duplicates))
        for data in (b'',b'not-base64',self.cipher[:-8],self.plain, b'x'*(codec.MAX_INPUT+1)):
            self.assertIsNone(codec.run(data))
        self.assertEqual(shared.CATALOG_KEY,b'Princie!')

    def test_fixed_download_and_no_redirects(self):
        class Response:
            status=200
            def __enter__(self): return self
            def __exit__(self,*_args): pass
            def read(inner,n): return self.cipher[:n]
        class Opener:
            def open(inner,req,timeout):
                self.assertEqual(req.full_url,codec.CATALOG_URL)
                self.assertEqual(req.get_header('User-agent'),'Dalvik/2.1.0')
                self.assertEqual(timeout,25)
                return Response()
        with patch.object(codec,'build_opener',return_value=Opener()):
            self.assertEqual(codec.decode(codec.fetch_catalog()),DOCUMENT)
        self.assertIsNone(codec._NoRedirect().redirect_request(None,None,302,'',{},'https://else.invalid'))

    def test_standalone_bundle_outside_repository_and_private_no_overwrite_output(self):
        committed=ROOT/'decoders/Python/apps/MTM_Tunnel_Lite/mtm_tunnel_lite.py'
        self.assertEqual(build(),committed.read_text())
        with tempfile.TemporaryDirectory() as folder:
            script=Path(folder)/'mtm_tunnel_lite.py';shutil.copyfile(committed,script)
            source=Path(folder)/'input.v2';source.write_bytes(self.cipher)
            for suffix in ('v2','json'):
                output=Path(folder)/('output-'+suffix+'.json')
                result=subprocess.run([sys.executable,'-I',str(script),str(source),'-o',str(output)],
                    cwd=folder,capture_output=True,timeout=20)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(json.loads(output.read_bytes()),DOCUMENT)
                self.assertEqual(output.stat().st_mode&0o777,0o600)
                again=subprocess.run([sys.executable,'-I',str(script),str(source),'-o',str(output)],
                    cwd=folder,capture_output=True,timeout=20)
                self.assertEqual(again.returncode,1)
                self.assertEqual(json.loads(output.read_bytes()),DOCUMENT)
            pasted=subprocess.run([sys.executable,'-I',str(script),'-','--stdout'],input=self.cipher,
                cwd=folder,capture_output=True,timeout=20)
            self.assertEqual(pasted.returncode,0,pasted.stderr)
            self.assertEqual(json.loads(pasted.stdout),DOCUMENT)

    def test_registry_preserves_frozen_v2_and_does_not_claim_generic_json(self):
        from cloud.workers.python.engine import load_file_engines,load_runtime_file_engines
        from spdecode.registry import get_decoder
        self.assertEqual(len(load_file_engines()),240)
        self.assertEqual(len(load_runtime_file_engines()),267)
        self.assertTrue(load_file_engines()['v2']['source'].endswith('/EV2RAY.py'))
        self.assertTrue(get_decoder('v2').script.endswith('/MTM_Tunnel_Lite/file_decoder.py'))
        self.assertNotIn('json',load_runtime_file_engines())


if __name__=='__main__': unittest.main()
