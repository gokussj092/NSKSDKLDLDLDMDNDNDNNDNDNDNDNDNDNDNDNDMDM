"""Focused complete server/user catalogs, independent JDK fixtures and worker."""
import base64
import json
from pathlib import Path
import subprocess
import sys
import unittest
from decoders.Python.apps.OnSpace_VPN import codec,server_catalog_decoder as catalog
ROOT=Path(__file__).resolve().parents[1]


class OnSpaceSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.v=json.loads((ROOT/'tests/golden/onspace_vpn_vectors.json').read_text())

    def test_jdk_documents_fields_and_complete_isolated_worker(self):
        v=self.v
        for name,expected in [('servers','expectedServers'),('users','expectedUsers')]:
            self.assertEqual(json.loads(catalog.run(v[name].encode())),v[expected])
        for item in v['fields']:
            self.assertEqual(codec.shared.decode_field(item['data'],key=codec.FIELD_KEY,rotation=24),item['expected'])
        bundle=catalog.pack_catalogs(v['servers'].encode(),v['users'].encode())
        expected={'provider':'onspace-vpn','complete':True,'catalogs':{'servers':v['expectedServers'],'users':v['expectedUsers']}}
        from cloud.workers.python.engine import decode_provider_catalog
        result=decode_provider_catalog('onspace-vpn',bundle)
        self.assertEqual(result['structuredJson'],expected)
        self.assertEqual(json.loads(result['rawText']),expected);self.assertFalse(result['isPartial'])

    def test_cli_bundle_stdin_outside_repository(self):
        v=self.v;data=catalog.pack_catalogs(v['servers'].encode(),v['users'].encode())
        p=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/OnSpace_VPN/server_catalog_decoder.py'),'--stdin'],input=data,cwd='/tmp',capture_output=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr.decode());self.assertEqual(json.loads(p.stdout),json.loads(catalog.run(data)))

    def test_invalid_records_cipher_sources_duplicates_limits_and_redirects(self):
        v=self.v;bundle=json.loads(catalog.pack_catalogs(v['servers'].encode(),v['users'].encode()))
        missing=json.loads(json.dumps(bundle));del missing['catalogs']['users']
        swapped=json.loads(json.dumps(bundle));swapped['catalogs']['users']=swapped['catalogs']['servers']
        duplicate='{"kind":"x","kind":"y","catalogs":{}}'
        for data in [b'',b'<html/>',b'private-invalid-data',v['servers'][:-12].encode(),b'x'*(catalog.MAX_BYTES+1),json.dumps(missing).encode(),json.dumps(swapped).encode(),duplicate.encode(),*(x.encode() for x in v['invalid'])]:
            with self.assertRaises(catalog.DecodeError) as e:catalog.run(data)
            self.assertNotIn('private-invalid-data',str(e.exception))
        with self.assertRaises(catalog.DecodeError):catalog._NoRedirect().redirect_request(None,None,None,None,None,None)

if __name__=='__main__':unittest.main()
