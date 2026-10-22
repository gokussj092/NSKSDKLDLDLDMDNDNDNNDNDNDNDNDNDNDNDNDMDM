"""Focused ProNeet offline catalog checks; no successful live feed is assumed."""
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from decoders.Python.apps.ProNeet_VPN import codec,server_catalog_decoder as catalog
ROOT=Path(__file__).resolve().parents[1]


class ProNeetSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.v=json.loads((ROOT/'tests/golden/proneet_vpn_vectors.json').read_text())

    def test_jdk_full_modes_fields_and_isolated_worker(self):
        v=self.v
        for name,key in [('usuario','expectedUsuario'),('token','expectedToken')]:
            self.assertEqual(json.loads(catalog.run(v[name].encode())),v[key])
        for item in v['fields']:self.assertEqual(codec.decode_field(item['data']),item['expected'])
        data=catalog.pack_catalogs(v['usuario'].encode(),v['token'].encode())
        from cloud.workers.python.engine import decode_provider_catalog
        result=decode_provider_catalog('proneet-vpn',data)
        expected={'provider':'proneet-vpn','complete':True,'catalogs':{'usuario':v['expectedUsuario'],'token':v['expectedToken']}}
        self.assertEqual(result['structuredJson'],expected);self.assertEqual(json.loads(result['rawText']),expected);self.assertFalse(result['isPartial'])

    def test_cli_bundle_stdin_outside_repository(self):
        data=catalog.pack_catalogs(self.v['usuario'].encode(),self.v['token'].encode())
        p=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/ProNeet_VPN/server_catalog_decoder.py'),'--stdin'],input=data,cwd='/tmp',capture_output=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr.decode());self.assertEqual(json.loads(p.stdout),json.loads(catalog.run(data)))

    def test_invalid_cipher_bundle_limits_and_blank_official_responses(self):
        bundle=json.loads(catalog.pack_catalogs(self.v['usuario'].encode(),self.v['token'].encode()));del bundle['catalogs']['token']
        for data in [b'',b'\n',b'<html/>',b'private-invalid-data',self.v['usuario'][:-12].encode(),b'x'*(catalog.MAX_BYTES+1),json.dumps(bundle).encode(),*(s.encode() for s in self.v['invalid'])]:
            with self.assertRaises(catalog.DecodeError) as e:catalog.run(data)
            self.assertNotIn('private-invalid-data',str(e.exception))
        class BlankResponse:
            status=200;headers={}
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def read(self,limit):return b'\n'
        class Opener:
            def open(self,request,timeout):
                self_url=request.full_url
                if self_url not in catalog.SOURCES.values():raise AssertionError('unexpected source')
                return BlankResponse()
        with patch.object(catalog,'build_opener',return_value=Opener()):
            for source in catalog.SOURCES:
                with self.assertRaises(catalog.DecodeError):catalog.download(source)
        with self.assertRaises(catalog.DecodeError):catalog._NoRedirect().redirect_request(None)

if __name__=='__main__':unittest.main()
