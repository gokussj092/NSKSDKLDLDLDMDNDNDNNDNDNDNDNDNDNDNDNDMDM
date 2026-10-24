"""Brief catalog/worker smoke checks; vectors produced independently with JDK AES."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from decoders.Python.apps.EUT_VPN import server_catalog_decoder as catalog

ROOT=Path(__file__).resolve().parents[1]
V=json.loads((ROOT/'tests/golden/eut_vpn_vectors.json').read_text())
DATA=json.dumps(V['source']).encode()

class EutVpnSmoke(unittest.TestCase):
    def test_complete_java_vector_and_isolated_worker(self):
        self.assertEqual(json.loads(catalog.run(DATA)),V['expected'])
        from cloud.workers.python.engine import decode_provider_catalog
        result=decode_provider_catalog('eut-vpn',DATA)
        self.assertEqual(result['structuredJson'],V['expected'])
        self.assertEqual(json.loads(result['rawText']),V['expected'])
        self.assertFalse(result['isPartial'])

    def test_invalid_or_missing_session_fails_explicitly(self):
        for data in [b'{"error":"Missing token"}',b'{"SERVER":[]}',b'{"data":"invalid"}',b'not-a-catalog']:
            with self.assertRaises(catalog.DecodeError):catalog.run(data)
        bad=json.loads(DATA);bad['SERVER'][-1]['data']='!' + bad['SERVER'][-1]['data'][1:]
        with self.assertRaises(catalog.DecodeError):catalog.run(json.dumps(bad).encode())
        with patch.dict(os.environ,{},clear=True),patch.object(catalog,'build_opener',side_effect=AssertionError('network')):
            with self.assertRaises(catalog.DecodeError):catalog.download()

    def test_cli_stdin_works_without_network(self):
        result=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/EUT_VPN/server_catalog_decoder.py'),'--stdin'],input=DATA,capture_output=True,cwd='/tmp',timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(json.loads(result.stdout),V['expected'])

if __name__=='__main__':unittest.main()
