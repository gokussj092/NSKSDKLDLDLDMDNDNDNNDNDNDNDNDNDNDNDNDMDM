"""Full .hat preservation and independent synthetic JCA/Node regression."""
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from decoders.Python.apps.HA_Tunnel_Plus.hat_decoder import (
    HatError, decode_hat, xor_java, MAX_INPUT_BYTES,
)

ROOT = Path(__file__).resolve().parents[1]
CODEC = ROOT / 'decoders/Python/apps/HA_Tunnel_Plus/hat_decoder.py'
VECTORS = ROOT / 'tests/golden/ha_tunnel_plus/jca-vectors.tsv'


class HatCompleteTests(unittest.TestCase):
    def test_independent_jca_vectors_including_utf16_surrogates(self):
        for line in VECTORS.read_text().splitlines():
            expected, field, carrier = line.split('\t')
            expected = base64.b64decode(expected).decode('utf-8')
            data = decode_hat(carrier.encode())
            self.assertEqual(data['profilev5']['custom_payload'], expected)
            self.assertEqual(data['unknown'], {'keep': [None, False, 23]})
            self.assertIs(data['protextras']['anti_sniff'], True)
            raw = decode_hat(carrier.encode(), decode_fields=False)
            self.assertEqual(raw['profilev5']['custom_payload'], field)
            self.assertEqual(xor_java(xor_java(expected)), expected)

    @unittest.skipUnless(shutil.which('node'), 'Node required for old complete-reader parity')
    def test_parity_with_complete_node_reader_on_fixtures_and_jca(self):
        carriers = [(ROOT/'hat'/name).read_bytes() for name in ('test.hat','test1.hat')]
        carriers += [line.split('\t')[2].encode() for line in VECTORS.read_text().splitlines()]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'input.hat'
            for carrier in carriers:
                path.write_bytes(carrier)
                output = subprocess.check_output(['node',str(ROOT/'cloud/workers/python/hat_complete.js'),str(path)])
                self.assertEqual(decode_hat(carrier), json.loads(output))

    def test_strict_base64_including_noncanonical_padding(self):
        # b'00' has canonical representation MDA=; MDB= has nonzero pad bits.
        for bad in (b'not base64!', b'AA==', b'MDB=', b'\xff', b'', b' '*16):
            with self.subTest(bad=bad), self.assertRaises(HatError):
                decode_hat(bad)
        with self.assertRaisesRegex(HatError,'INPUT_TOO_LARGE'):
            decode_hat(b'A' * (MAX_INPUT_BYTES + 1))

    def test_cli_private_output_no_clobber_and_safe_errors(self):
        with tempfile.TemporaryDirectory() as folder:
            source = ROOT/'hat/test.hat'
            target = Path(folder)/'result.json'
            result = subprocess.run([sys.executable,str(CODEC),str(source),'-o',str(target)],capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout,b'')
            self.assertEqual(target.stat().st_mode & 0o777,0o600)
            before = target.read_bytes()
            result = subprocess.run([sys.executable,str(CODEC),str(source),'-o',str(target)],capture_output=True)
            self.assertEqual(result.returncode,1)
            self.assertEqual(result.stderr,b'FILE_ERROR\n')
            self.assertEqual(target.read_bytes(),before)
            result = subprocess.run([sys.executable,str(CODEC),'-'],input=b'private bad input!',capture_output=True)
            self.assertEqual(result.returncode,1)
            self.assertEqual(result.stdout,b'')
            self.assertEqual(result.stderr,b'INVALID_BASE64\n')


if __name__ == '__main__':
    unittest.main()
