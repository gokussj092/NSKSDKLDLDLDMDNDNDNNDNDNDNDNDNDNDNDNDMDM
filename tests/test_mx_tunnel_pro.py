"""Focused Mx Tunnel PRO catalog checks, independent JDK vectors and worker."""
import base64
import json
from pathlib import Path
import subprocess
import sys
import unittest
from decoders.Python.apps.Mx_Tunnel_PRO import server_catalog_decoder as catalog
ROOT=Path(__file__).resolve().parents[1]
V=json.loads((ROOT/'tests/golden/mx_tunnel_pro_vectors.json').read_text())


class MxTunnelProSmoke(unittest.TestCase):
    def test_complete_jdk_vector_worker_and_historical_key(self):
        data=V['catalog'].encode();expected=V['expected']
        self.assertEqual(json.loads(catalog.run(data)),expected)
        from cloud.workers.python.engine import decode_provider_catalog
        result=decode_provider_catalog('mx-tunnel-pro',data)
        self.assertEqual(result['structuredJson'],expected)
        self.assertEqual(json.loads(result['rawText']),expected);self.assertFalse(result['isPartial'])
        # Parameterizing the primitive must preserve the HX/TRV/4U default key.
        from decoders.Python.apps.HX_Tunnel_VPN import HX_Tunnel_VPN as hx
        old=json.loads((ROOT/'tests/golden/hx_tunnel_vectors.json').read_text())
        self.assertEqual(hx.decode(old['catalog']),old['expectedCatalog'])
        self.assertIsNone(hx.run(data))

    def test_cli_stdin_outside_repository(self):
        p=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/Mx_Tunnel_PRO/server_catalog_decoder.py'),'--stdin'],input=V['catalog'].encode(),cwd='/tmp',capture_output=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr.decode());self.assertEqual(json.loads(p.stdout),V['expected'])

    def test_invalid_sections_lengths_limits_and_redirects(self):
        raw=base64.b64decode(V['catalog'])
        for data in [b'',b'<html/>',b'private-invalid-data',base64.b64encode(raw[:-1]),V['catalog'][:-12].encode(),b'x'*(catalog.MAX_BYTES+1),*(s.encode() for s in V['invalid'])]:
            with self.assertRaises(catalog.DecodeError) as e:catalog.run(data)
            self.assertNotIn('private-invalid-data',str(e.exception))
        with self.assertRaises(catalog.DecodeError):catalog._NoRedirect().redirect_request(None)

if __name__=='__main__':unittest.main()
