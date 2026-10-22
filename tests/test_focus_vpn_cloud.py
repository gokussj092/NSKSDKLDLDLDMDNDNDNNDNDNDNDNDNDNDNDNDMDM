"""Targeted Focus build-59 catalog smoke checks; no full regression run required."""
import json
from pathlib import Path
import subprocess
import sys
import unittest
from decoders.Python.apps.Focus_VPN_Cloud import server_catalog_decoder as catalog
ROOT=Path(__file__).resolve().parents[1]
V=json.loads((ROOT/'tests/golden/focus_vpn_cloud_vectors.json').read_text())

class FocusVpnCloudSmoke(unittest.TestCase):
    def test_complete_jdk_vector_and_isolated_worker(self):
        data=V['catalog'].encode();expected=V['expected']
        self.assertEqual(json.loads(catalog.run(data)),expected)
        from cloud.workers.python.engine import decode_provider_catalog
        result=decode_provider_catalog('focus-vpn-cloud',data)
        self.assertEqual(result['structuredJson'],expected)
        self.assertEqual(json.loads(result['rawText']),expected);self.assertFalse(result['isPartial'])

    def test_cli_stdin_outside_repository(self):
        p=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/Focus_VPN_Cloud/server_catalog_decoder.py'),'--stdin'],input=V['catalog'].encode(),cwd='/tmp',capture_output=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr.decode());self.assertEqual(json.loads(p.stdout),V['expected'])

    def test_invalid_input_and_redirects_are_rejected(self):
        for data in [b'',b'<html/>',b'private-invalid-data',V['catalog'][:-1].encode(),b'x'*(catalog.MAX_BYTES+1)]:
            with self.assertRaises(catalog.DecodeError) as e:catalog.run(data)
            self.assertNotIn('private-invalid-data',str(e.exception))
        with self.assertRaises(catalog.DecodeError):catalog._NoRedirect().redirect_request(None)

if __name__=='__main__':unittest.main()
